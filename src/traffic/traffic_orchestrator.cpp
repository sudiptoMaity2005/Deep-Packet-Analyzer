#include "traffic/traffic_orchestrator.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace DPI {

std::string ingestionModeToString(IngestionMode mode) {
    switch (mode) {
        case IngestionMode::CHRONOLOGICAL_MERGE: return "chronological-merge";
        case IngestionMode::FAIR_ROUND_ROBIN:     return "fair-round-robin";
        default:                                 return "unknown";
    }
}

IngestionMode stringToIngestionMode(const std::string& mode_str) {
    std::string s = mode_str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (s == "rr" || s == "round-robin" || s == "fair-round-robin" || s == "round_robin") {
        return IngestionMode::FAIR_ROUND_ROBIN;
    }
    return IngestionMode::CHRONOLOGICAL_MERGE;
}

TrafficOrchestrator::TrafficOrchestrator(const OrchestratorConfig& config)
    : config_(config), shaper_(config.shaper_config) {
}

TrafficOrchestrator::~TrafficOrchestrator() {
    for (auto& s : sources_) {
        if (s && s->reader && s->reader->isOpen()) {
            s->reader->close();
        }
    }
}

void TrafficOrchestrator::configure(const OrchestratorConfig& config) {
    config_ = config;
    shaper_.configure(config.shaper_config);
}

bool TrafficOrchestrator::addSource(const std::string& pcap_file) {
    auto stream = std::make_unique<SourceStream>();
    stream->id = sources_.size();
    stream->filename = pcap_file;
    stream->reader = std::make_unique<PacketAnalyzer::PcapReader>();

    if (!stream->reader->open(pcap_file)) {
        std::cerr << "[Orchestrator] Failed to open PCAP source: " << pcap_file << "\n";
        return false;
    }

    if (!header_captured_) {
        global_header_ = stream->reader->getGlobalHeader();
        header_captured_ = true;
    }

    // Prefetch first packet for queueing
    if (stream->reader->readNextPacket(stream->current_raw)) {
        stream->has_packet = true;
        stream->packets_read++;
        stream->bytes_read += stream->current_raw.data.size();
    } else {
        stream->has_packet = false;
        stream->eof = true;
    }

    if (config_.verbose) {
        std::cout << "[Orchestrator] Registered source #" << stream->id
                  << ": " << pcap_file << "\n";
    }

    sources_.push_back(std::move(stream));
    return true;
}

bool TrafficOrchestrator::addSources(const std::vector<std::string>& pcap_files) {
    bool all_ok = true;
    for (const auto& file : pcap_files) {
        if (!addSource(file)) {
            all_ok = false;
        }
    }
    return all_ok && !sources_.empty();
}

PacketJob TrafficOrchestrator::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                               const PacketAnalyzer::ParsedPacket& parsed,
                                               uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;

    job.tuple.ip_version = parsed.ip_version;
    if (parsed.ip_version == 4) {
        job.tuple.src_ip = parsed.src_ip_v4;
        job.tuple.dst_ip = parsed.dest_ip_v4;
    } else {
        job.tuple.src_ip6 = parsed.src_ip_v6;
        job.tuple.dst_ip6 = parsed.dest_ip_v6;
    }
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;

    job.tcp_flags = parsed.tcp_flags;
    job.ttl = parsed.ttl;
    job.window_size = parsed.window_size;
    job.data = raw.data;

    job.eth_offset = 0;
    job.ip_offset = 14;
    job.payload_offset = parsed.payload_offset;
    job.payload_length = parsed.payload_length;
    if (job.payload_length > 0 && job.payload_offset < job.data.size()) {
        job.payload_data = job.data.data() + job.payload_offset;
    } else {
        job.payload_data = nullptr;
    }

    return job;
}

bool TrafficOrchestrator::processAndDispatch(PacketAnalyzer::RawPacket& raw,
                                             size_t /*stream_id*/,
                                             uint32_t packet_id,
                                             std::function<void(const PacketJob&)>& on_packet_dispatched) {
    PacketAnalyzer::ParsedPacket parsed;
    if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
        return false;
    }

    if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
        return false;
    }

    PacketJob job = createPacketJob(raw, parsed, packet_id);

    // Enforce Traffic Shaping & QoS Pacing
    shaper_.shape(job);

    total_packets_++;
    total_bytes_ += raw.data.size();
    total_dispatched_++;

    if (lb_manager_) {
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(job);
    }

    if (on_packet_dispatched) {
        on_packet_dispatched(job);
    }

    return true;
}

uint64_t TrafficOrchestrator::run(std::atomic<bool>& running,
                                  std::function<void(const PacketAnalyzer::PcapGlobalHeader&)> on_header,
                                  std::function<void(const PacketJob&)> on_packet_dispatched) {
    if (sources_.empty()) {
        std::cerr << "[Orchestrator] Warning: No input PCAP sources configured\n";
        return 0;
    }

    if (on_header && header_captured_) {
        on_header(global_header_);
    }

    start_time_ = std::chrono::steady_clock::now();

    if (config_.ingestion_mode == IngestionMode::CHRONOLOGICAL_MERGE) {
        runChronologicalMerge(running, on_packet_dispatched);
    } else {
        runFairRoundRobin(running, on_packet_dispatched);
    }

    end_time_ = std::chrono::steady_clock::now();
    return total_dispatched_.load();
}

uint64_t TrafficOrchestrator::runChronologicalMerge(std::atomic<bool>& running,
                                                    std::function<void(const PacketJob&)>& on_packet_dispatched) {
    std::priority_queue<HeapNode, std::vector<HeapNode>, std::greater<HeapNode>> min_heap;

    // Populate min-heap with first packet from each source
    for (size_t i = 0; i < sources_.size(); ++i) {
        if (sources_[i]->has_packet) {
            min_heap.push({
                sources_[i]->current_raw.header.ts_sec,
                sources_[i]->current_raw.header.ts_usec,
                i
            });
        }
    }

    uint32_t packet_id = 0;

    while (!min_heap.empty() && running) {
        HeapNode top = min_heap.top();
        min_heap.pop();

        auto& stream = sources_[top.stream_index];
        PacketAnalyzer::RawPacket raw = std::move(stream->current_raw);

        // Replenish stream buffer with its next packet
        if (stream->reader->readNextPacket(stream->current_raw)) {
            stream->has_packet = true;
            stream->packets_read++;
            stream->bytes_read += stream->current_raw.data.size();
            min_heap.push({
                stream->current_raw.header.ts_sec,
                stream->current_raw.header.ts_usec,
                top.stream_index
            });
        } else {
            stream->has_packet = false;
            stream->eof = true;
        }

        processAndDispatch(raw, top.stream_index, packet_id++, on_packet_dispatched);
    }

    return total_dispatched_.load();
}

uint64_t TrafficOrchestrator::runFairRoundRobin(std::atomic<bool>& running,
                                                std::function<void(const PacketJob&)>& on_packet_dispatched) {
    uint32_t packet_id = 0;
    size_t active_count = 0;

    for (const auto& s : sources_) {
        if (!s->eof) active_count++;
    }

    while (active_count > 0 && running) {
        for (size_t i = 0; i < sources_.size() && running; ++i) {
            auto& stream = sources_[i];
            if (stream->eof) continue;

            PacketAnalyzer::RawPacket raw;
            if (stream->has_packet) {
                raw = std::move(stream->current_raw);
                stream->has_packet = false;
            } else {
                if (!stream->reader->readNextPacket(raw)) {
                    stream->eof = true;
                    if (active_count > 0) active_count--;
                    continue;
                }
                stream->packets_read++;
                stream->bytes_read += raw.data.size();
            }

            processAndDispatch(raw, i, packet_id++, on_packet_dispatched);
        }
    }

    return total_dispatched_.load();
}

OrchestratorStats TrafficOrchestrator::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    OrchestratorStats stats;
    stats.total_packets = total_packets_.load();
    stats.total_bytes = total_bytes_.load();
    stats.total_dispatched = total_dispatched_.load();

    auto end = (end_time_ > start_time_) ? end_time_ : std::chrono::steady_clock::now();
    stats.elapsed_seconds = std::chrono::duration<double>(end - start_time_).count();

    if (stats.elapsed_seconds > 0.0) {
        stats.throughput_pps = static_cast<double>(stats.total_packets) / stats.elapsed_seconds;
        stats.throughput_mbps = (static_cast<double>(stats.total_bytes) * 8.0) /
                                (stats.elapsed_seconds * 1000000.0);
    }

    for (const auto& s : sources_) {
        HostSourceStats h;
        h.source_id = s->id;
        h.filename = s->filename;
        h.packets_read = s->packets_read;
        h.bytes_read = s->bytes_read;
        h.eof = s->eof;
        stats.per_source_stats.push_back(h);
    }

    stats.shaper_stats = shaper_.getStats();
    return stats;
}

std::string TrafficOrchestrator::generateReport() const {
    OrchestratorStats stats = getStats();
    std::stringstream ss;

    ss << "\n================================================================================\n";
    ss << "               TRAFFIC ORCHESTRATOR & LOAD SHAPING REPORT                       \n";
    ss << "================================================================================\n";
    ss << " Ingestion Mode:          " << ingestionModeToString(config_.ingestion_mode) << "\n";
    ss << " Active Capture Sources:  " << sources_.size() << " host files\n";
    ss << " Total Packets Read:      " << stats.total_packets << "\n";
    ss << " Total Dispatched:        " << stats.total_dispatched << "\n";
    ss << " Total Volume:            " << std::fixed << std::setprecision(2)
       << (stats.total_bytes / (1024.0 * 1024.0)) << " MB (" << stats.total_bytes << " bytes)\n";
    ss << " Elapsed Processing Time: " << stats.elapsed_seconds << " s\n";
    ss << " Ingestion Throughput:    " << std::fixed << std::setprecision(1)
       << stats.throughput_pps << " pkts/sec (" << stats.throughput_mbps << " Mbps)\n";

    ss << "--------------------------------------------------------------------------------\n";
    ss << " Multi-Host Source Ingestion Breakdown:\n";
    for (const auto& src : stats.per_source_stats) {
        ss << "  [Source #" << src.source_id << "] " << src.filename
           << " -> " << src.packets_read << " pkts ("
           << (src.bytes_read / 1024.0) << " KB)"
           << (src.eof ? " [EOF reached]" : "") << "\n";
    }

    ss << "--------------------------------------------------------------------------------\n";
    ss << " Traffic Shaper & QoS Pacing:\n";
    ss << "  Algorithm:              " << shaperAlgorithmToString(config_.shaper_config.algorithm) << "\n";
    ss << "  Rate Limit:             " << config_.shaper_config.rate_limit_pps << " PPS\n";
    ss << "  Burst Capacity:         " << config_.shaper_config.burst_capacity << " tokens\n";
    ss << "  QoS Expedited Forward:  " << (config_.shaper_config.enable_qos_priority ? "ENABLED (SYN/FIN/RST/DNS bypass)" : "DISABLED") << "\n";
    ss << "  Burst Packets Admitted: " << stats.shaper_stats.burst_packets << "\n";
    ss << "  Paced/Delayed Packets:  " << stats.shaper_stats.delayed_packets << "\n";
    ss << "  Expedited High-Priority:" << stats.shaper_stats.high_priority_expedited << "\n";
    ss << "  Accumulated Delay Time: " << stats.shaper_stats.total_delay_seconds << " s\n";
    ss << "================================================================================\n";

    return ss.str();
}

} // namespace DPI

