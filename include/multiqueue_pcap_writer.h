#ifndef MULTIQUEUE_PCAP_WRITER_H
#define MULTIQUEUE_PCAP_WRITER_H

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <chrono>
#include "types.h"
#include "pcap_reader.h"
#include "thread_safe_queue.h"
#include "traffic_shaper.h"

namespace DPI {

// ============================================================================
// Multi-Queue Shard Routing Policies
// ============================================================================
enum class ShardRoutingPolicy {
    LEAST_LOADED,    // Routes packet to the shard queue with the minimum backlog/depth
    FLOW_AFFINITY,   // Uses symmetric 5-tuple hash to pin entire flows to the same PCAP
    ROUND_ROBIN      // Uniformly rotates across PCAP shard queues
};

std::string routingPolicyToString(ShardRoutingPolicy policy);
ShardRoutingPolicy stringToRoutingPolicy(const std::string& name);

// ============================================================================
// Per-Shard Telemetry & Live Load Metrics
// ============================================================================
struct PcapShardStats {
    size_t shard_id = 0;
    std::string filename;
    uint64_t packets_written = 0;
    uint64_t bytes_written = 0;
    size_t current_queue_depth = 0;
    size_t pending_bytes = 0;
    uint64_t dropped_packets = 0;
    double write_rate_pps = 0.0;
    ShaperStats shaper_stats;
};

// ============================================================================
// Multi-Queue Capture Configuration
// ============================================================================
struct MultiQueueCaptureConfig {
    size_t num_shards = 1;                              // Number of concurrent PCAP queues/files
    ShardRoutingPolicy routing_policy = ShardRoutingPolicy::LEAST_LOADED;
    size_t max_queue_depth = 10000;                     // Max queue size per shard before backpressure
    ShaperConfig shaper_config;                         // Pacing shaper per shard (Token/Leaky Bucket)
    bool verbose = false;
};

// ============================================================================
// PCAP Shard Sink
// Dedicated worker thread + bounded queue + Traffic Shaper writing to one PCAP.
// ============================================================================
class PcapShardSink {
public:
    PcapShardSink(size_t shard_id,
                  const std::string& filename,
                  size_t max_queue_depth,
                  const ShaperConfig& shaper_cfg);
    ~PcapShardSink();

    // Open file and write global PCAP header
    bool open(const PacketAnalyzer::PcapGlobalHeader& header);
    
    // Stop thread and flush queue
    void close();

    // Enqueue packet for asynchronous shaped write
    bool enqueue(PacketJob job);

    // Live load inspection
    size_t getQueueDepth() const { return queue_.size(); }
    size_t getPendingBytes() const { return pending_bytes_.load(); }
    size_t getShardId() const { return shard_id_; }
    const std::string& getFilename() const { return filename_; }

    PcapShardStats getStats() const;

private:
    size_t shard_id_;
    std::string filename_;
    std::ofstream file_;
    std::mutex file_mutex_;

    ThreadSafeQueue<PacketJob> queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_{false};
    TrafficShaper shaper_;

    std::atomic<size_t> pending_bytes_{0};
    std::atomic<uint64_t> packets_written_{0};
    std::atomic<uint64_t> bytes_written_{0};
    std::atomic<uint64_t> dropped_packets_{0};

    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_write_time_;

    void writerLoop();
    void writePacketDirect(const PacketJob& job);
};

// ============================================================================
// Multi-Queue Packet Capture Interface (Demux / Sharding Orchestrator)
// Inspects live queue loads of all PCAP shards and steers packets dynamically.
// ============================================================================
class MultiQueueCaptureInterface {
public:
    MultiQueueCaptureInterface(const MultiQueueCaptureConfig& config = MultiQueueCaptureConfig{});
    ~MultiQueueCaptureInterface();

    // Initialize shards: either with a base filename (auto-generated suffixes)
    // or explicit list of filenames
    bool initialize(const std::string& base_output_file,
                    const PacketAnalyzer::PcapGlobalHeader& header);
    bool initialize(const std::vector<std::string>& shard_filenames,
                    const PacketAnalyzer::PcapGlobalHeader& header);

    // Dispatch a packet: checks live load / policy and enqueues to optimal shard
    bool dispatch(PacketJob job);

    // Stop all writer threads and flush all queues
    void close();

    // Live load inspection
    size_t getLeastLoadedShardIndex() const;
    std::vector<PcapShardStats> getAllShardStats() const;
    std::string generateLiveLoadReport() const;

    size_t getNumShards() const { return shards_.size(); }
    const MultiQueueCaptureConfig& getConfig() const { return config_; }

private:
    MultiQueueCaptureConfig config_;
    std::vector<std::unique_ptr<PcapShardSink>> shards_;
    std::atomic<uint64_t> round_robin_counter_{0};
    FiveTupleHash flow_hasher_;
    bool initialized_ = false;
    mutable std::recursive_mutex init_mutex_;
};

} // namespace DPI

#endif // MULTIQUEUE_PCAP_WRITER_H
