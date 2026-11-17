#include "traffic/multiqueue_pcap_writer.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace DPI {

std::string routingPolicyToString(ShardRoutingPolicy policy) {
    switch (policy) {
        case ShardRoutingPolicy::LEAST_LOADED:  return "least-loaded";
        case ShardRoutingPolicy::FLOW_AFFINITY: return "flow-affinity";
        case ShardRoutingPolicy::ROUND_ROBIN:   return "round-robin";
        default:                                return "unknown";
    }
}

ShardRoutingPolicy stringToRoutingPolicy(const std::string& name) {
    std::string s = name;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (s == "flow" || s == "flow-affinity" || s == "flow_affinity" || s == "hash") {
        return ShardRoutingPolicy::FLOW_AFFINITY;
    }
    if (s == "rr" || s == "round-robin" || s == "round_robin") {
        return ShardRoutingPolicy::ROUND_ROBIN;
    }
    return ShardRoutingPolicy::LEAST_LOADED;
}

// ============================================================================
// PcapShardSink Implementation
// ============================================================================

PcapShardSink::PcapShardSink(size_t shard_id,
                             const std::string& filename,
                             size_t max_queue_depth,
                             const ShaperConfig& shaper_cfg)
    : shard_id_(shard_id),
      filename_(filename),
      queue_(max_queue_depth),
      shaper_(shaper_cfg) {
}

PcapShardSink::~PcapShardSink() {
    close();
}

bool PcapShardSink::open(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(file_mutex_);
    file_.open(filename_, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapShardSink #" << shard_id_ << "] Failed to open: " << filename_ << "\n";
        return false;
    }

    file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!file_.good()) {
        std::cerr << "[PcapShardSink #" << shard_id_ << "] Failed to write header to: " << filename_ << "\n";
        file_.close();
        return false;
    }

    running_ = true;
    start_time_ = std::chrono::steady_clock::now();
    last_write_time_ = start_time_;
    writer_thread_ = std::thread(&PcapShardSink::writerLoop, this);

    return true;
}

void PcapShardSink::close() {
    if (!running_.exchange(false)) {
        return; // Already closed
    }

    queue_.shutdown();

    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }

    std::lock_guard<std::mutex> lock(file_mutex_);
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}

bool PcapShardSink::enqueue(PacketJob job) {
    if (!running_) return false;

    pending_bytes_ += job.data.size();
    queue_.push(std::move(job));
    return true;
}

void PcapShardSink::writerLoop() {
    while (running_ || !queue_.empty()) {
        auto job_opt = queue_.popWithTimeout(std::chrono::milliseconds(50));
        if (job_opt) {
            // Apply Traffic Shaping & Pacing before committing to disk
            shaper_.shape(*job_opt);

            writePacketDirect(*job_opt);

            if (pending_bytes_ >= job_opt->data.size()) {
                pending_bytes_ -= job_opt->data.size();
            } else {
                pending_bytes_ = 0;
            }

            packets_written_++;
            bytes_written_ += job_opt->data.size();
            last_write_time_ = std::chrono::steady_clock::now();
        }
    }
}

void PcapShardSink::writePacketDirect(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(file_mutex_);
    if (!file_.is_open()) return;

    PacketAnalyzer::PcapPacketHeader pkt_hdr;
    pkt_hdr.ts_sec = job.ts_sec;
    pkt_hdr.ts_usec = job.ts_usec;
    pkt_hdr.incl_len = static_cast<uint32_t>(job.data.size());
    pkt_hdr.orig_len = static_cast<uint32_t>(job.data.size());

    file_.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
    file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

PcapShardStats PcapShardSink::getStats() const {
    PcapShardStats stats;
    stats.shard_id = shard_id_;
    stats.filename = filename_;
    stats.packets_written = packets_written_.load();
    stats.bytes_written = bytes_written_.load();
    stats.current_queue_depth = queue_.size();
    stats.pending_bytes = pending_bytes_.load();
    stats.dropped_packets = dropped_packets_.load();

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_time_).count();
    if (elapsed > 0.0) {
        stats.write_rate_pps = static_cast<double>(stats.packets_written) / elapsed;
    }

    stats.shaper_stats = shaper_.getStats();
    return stats;
}

// ============================================================================
// MultiQueueCaptureInterface Implementation
// ============================================================================

MultiQueueCaptureInterface::MultiQueueCaptureInterface(const MultiQueueCaptureConfig& config)
    : config_(config) {
}

MultiQueueCaptureInterface::~MultiQueueCaptureInterface() {
    close();
}

bool MultiQueueCaptureInterface::initialize(const std::string& base_output_file,
                                            const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::recursive_mutex> lock(init_mutex_);
    if (initialized_) close();

    std::vector<std::string> filenames;
    if (config_.num_shards <= 1) {
        filenames.push_back(base_output_file);
    } else {
        std::string base = base_output_file;
        std::string ext = ".pcap";
        if (base.size() >= 5 && base.substr(base.size() - 5) == ".pcap") {
            base = base.substr(0, base.size() - 5);
        }
        for (size_t i = 0; i < config_.num_shards; ++i) {
            filenames.push_back(base + "_shard_" + std::to_string(i) + ext);
        }
    }

    return initialize(filenames, header);
}

bool MultiQueueCaptureInterface::initialize(const std::vector<std::string>& shard_filenames,
                                            const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::recursive_mutex> lock(init_mutex_);
    if (shard_filenames.empty()) {
        std::cerr << "[MultiQueueCapture] No output filenames specified\n";
        return false;
    }

    shards_.clear();
    for (size_t i = 0; i < shard_filenames.size(); ++i) {
        auto shard = std::make_unique<PcapShardSink>(
            i,
            shard_filenames[i],
            config_.max_queue_depth,
            config_.shaper_config
        );

        if (!shard->open(header)) {
            std::cerr << "[MultiQueueCapture] Failed to open shard: " << shard_filenames[i] << "\n";
            close();
            return false;
        }

        if (config_.verbose) {
            std::cout << "[MultiQueueCapture] Initialized shard #" << i << ": "
                      << shard_filenames[i] << " (Queue depth: " << config_.max_queue_depth << ")\n";
        }

        shards_.push_back(std::move(shard));
    }

    initialized_ = true;
    return true;
}

size_t MultiQueueCaptureInterface::getLeastLoadedShardIndex() const {
    if (shards_.empty()) return 0;

    size_t best_idx = 0;
    size_t min_depth = shards_[0]->getQueueDepth();
    size_t min_bytes = shards_[0]->getPendingBytes();

    for (size_t i = 1; i < shards_.size(); ++i) {
        size_t depth = shards_[i]->getQueueDepth();
        size_t bytes = shards_[i]->getPendingBytes();

        if (depth < min_depth || (depth == min_depth && bytes < min_bytes)) {
            min_depth = depth;
            min_bytes = bytes;
            best_idx = i;
        }
    }

    return best_idx;
}

bool MultiQueueCaptureInterface::dispatch(PacketJob job) {
    if (!initialized_ || shards_.empty()) {
        return false;
    }

    size_t target_idx = 0;

    switch (config_.routing_policy) {
        case ShardRoutingPolicy::LEAST_LOADED:
            target_idx = getLeastLoadedShardIndex();
            break;
        case ShardRoutingPolicy::FLOW_AFFINITY:
            target_idx = flow_hasher_(job.tuple) % shards_.size();
            break;
        case ShardRoutingPolicy::ROUND_ROBIN:
            target_idx = (round_robin_counter_++) % shards_.size();
            break;
    }

    return shards_[target_idx]->enqueue(std::move(job));
}

void MultiQueueCaptureInterface::close() {
    std::lock_guard<std::recursive_mutex> lock(init_mutex_);
    for (auto& shard : shards_) {
        if (shard) {
            shard->close();
        }
    }
    initialized_ = false;
}

std::vector<PcapShardStats> MultiQueueCaptureInterface::getAllShardStats() const {
    std::vector<PcapShardStats> results;
    for (const auto& shard : shards_) {
        if (shard) {
            results.push_back(shard->getStats());
        }
    }
    return results;
}

std::string MultiQueueCaptureInterface::generateLiveLoadReport() const {
    auto stats = getAllShardStats();
    std::stringstream ss;

    ss << "\n================================================================================\n";
    ss << "          MULTI-QUEUE PCAP CAPTURE INTERFACE — LIVE LOAD & STORAGE REPORT        \n";
    ss << "================================================================================\n";
    ss << " Shard Routing Policy:  " << routingPolicyToString(config_.routing_policy) << "\n";
    ss << " Active PCAP Queues:    " << stats.size() << " dedicated disk sinks\n";
    ss << " Queue Capacity:        " << config_.max_queue_depth << " pkts/queue\n";
    ss << " Shard Shaper:          " << shaperAlgorithmToString(config_.shaper_config.algorithm);
    if (config_.shaper_config.rate_limit_pps > 0.0) {
        ss << " (" << config_.shaper_config.rate_limit_pps << " PPS cap)";
    }
    ss << "\n--------------------------------------------------------------------------------\n";
    ss << " Shard Storage & Queue Load Distribution:\n";

    uint64_t total_pkts = 0;
    uint64_t total_bytes = 0;

    for (const auto& s : stats) {
        total_pkts += s.packets_written;
        total_bytes += s.bytes_written;

        ss << "  [Shard #" << s.shard_id << "] " << s.filename << "\n"
           << "    -> Written:     " << s.packets_written << " pkts ("
           << std::fixed << std::setprecision(2) << (s.bytes_written / 1024.0) << " KB)\n"
           << "    -> Queue Depth: " << s.current_queue_depth << " pending pkts ("
           << s.pending_bytes << " bytes in flight)\n"
           << "    -> Rate:        " << std::setprecision(1) << s.write_rate_pps << " pkts/sec\n";
        if (config_.shaper_config.algorithm != ShaperAlgorithm::NONE) {
            ss << "    -> Shaper:      " << s.shaper_stats.burst_packets << " burst admitted, "
               << s.shaper_stats.delayed_packets << " delayed, "
               << s.shaper_stats.high_priority_expedited << " expedited\n";
        }
    }

    ss << "--------------------------------------------------------------------------------\n";
    ss << " Total Aggregate Captured: " << total_pkts << " packets ("
       << std::fixed << std::setprecision(2) << (total_bytes / (1024.0 * 1024.0)) << " MB)\n";
    ss << "================================================================================\n";

    return ss.str();
}

} // namespace DPI
