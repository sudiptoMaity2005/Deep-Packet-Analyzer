#ifndef TRAFFIC_ORCHESTRATOR_H
#define TRAFFIC_ORCHESTRATOR_H

#include <string>
#include <vector>
#include <memory>
#include <queue>
#include <chrono>
#include <atomic>
#include <functional>
#include <mutex>
#include "core/types.h"
#include "protocol/pcap_reader.h"
#include "protocol/packet_parser.h"
#include "traffic/traffic_shaper.h"
#include "core/load_balancer.h"

namespace DPI {

// ============================================================================
// Multi-Source Ingestion Strategy
// ============================================================================
enum class IngestionMode {
    CHRONOLOGICAL_MERGE,  // K-way min-heap merge by microsecond timestamps
    FAIR_ROUND_ROBIN      // Interleaves packets fairly across host capture sources
};

std::string ingestionModeToString(IngestionMode mode);
IngestionMode stringToIngestionMode(const std::string& mode_str);

// ============================================================================
// Orchestrator Configuration
// ============================================================================
struct OrchestratorConfig {
    IngestionMode ingestion_mode = IngestionMode::CHRONOLOGICAL_MERGE;
    ShaperConfig shaper_config;
    bool verbose = false;
};

// ============================================================================
// Source Capture Statistics
// ============================================================================
struct HostSourceStats {
    size_t source_id = 0;
    std::string filename;
    uint64_t packets_read = 0;
    uint64_t bytes_read = 0;
    bool eof = false;
};

// ============================================================================
// Orchestrator Aggregate Telemetry
// ============================================================================
struct OrchestratorStats {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_dispatched = 0;
    double elapsed_seconds = 0.0;
    double throughput_pps = 0.0;
    double throughput_mbps = 0.0;
    std::vector<HostSourceStats> per_source_stats;
    ShaperStats shaper_stats;
};

// ============================================================================
// Traffic Orchestrator
// Aggregates multiple PCAPs, merges flows, applies token/leaky shaping & QoS,
// and balances workloads across downstream DPI Load Balancers.
// ============================================================================
class TrafficOrchestrator {
public:
    TrafficOrchestrator(const OrchestratorConfig& config = OrchestratorConfig{});
    ~TrafficOrchestrator();

    // Register capture sources
    bool addSource(const std::string& pcap_file);
    bool addSources(const std::vector<std::string>& pcap_files);

    // Bind downstream load balancers
    void setLoadBalancerManager(LBManager* lb_manager) { lb_manager_ = lb_manager; }

    // Configuration
    void configure(const OrchestratorConfig& config);
    const OrchestratorConfig& getConfig() const { return config_; }

    // Execute orchestration loop
    uint64_t run(std::atomic<bool>& running,
                 std::function<void(const PacketAnalyzer::PcapGlobalHeader&)> on_header = nullptr,
                 std::function<void(const PacketJob&)> on_packet_dispatched = nullptr);

    // Telemetry & Reporting
    OrchestratorStats getStats() const;
    std::string generateReport() const;

    TrafficShaper& getShaper() { return shaper_; }
    const TrafficShaper& getShaper() const { return shaper_; }

    const PacketAnalyzer::PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    size_t getSourceCount() const { return sources_.size(); }

private:
    struct SourceStream {
        size_t id = 0;
        std::string filename;
        std::unique_ptr<PacketAnalyzer::PcapReader> reader;
        PacketAnalyzer::RawPacket current_raw;
        bool has_packet = false;
        uint64_t packets_read = 0;
        uint64_t bytes_read = 0;
        bool eof = false;
    };

    struct HeapNode {
        uint32_t ts_sec;
        uint32_t ts_usec;
        size_t stream_index;

        bool operator>(const HeapNode& other) const {
            if (ts_sec != other.ts_sec) {
                return ts_sec > other.ts_sec;
            }
            return ts_usec > other.ts_usec;
        }
    };

    OrchestratorConfig config_;
    LBManager* lb_manager_ = nullptr;
    TrafficShaper shaper_;
    PacketAnalyzer::PcapGlobalHeader global_header_{};
    bool header_captured_ = false;

    std::vector<std::unique_ptr<SourceStream>> sources_;

    // Performance telemetry
    mutable std::mutex stats_mutex_;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> total_dispatched_{0};

    // Helper routines
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                              const PacketAnalyzer::ParsedPacket& parsed,
                              uint32_t packet_id);

    bool processAndDispatch(PacketAnalyzer::RawPacket& raw,
                            size_t stream_id,
                            uint32_t packet_id,
                            std::function<void(const PacketJob&)>& on_packet_dispatched);

    uint64_t runChronologicalMerge(std::atomic<bool>& running,
                                   std::function<void(const PacketJob&)>& on_packet_dispatched);

    uint64_t runFairRoundRobin(std::atomic<bool>& running,
                               std::function<void(const PacketJob&)>& on_packet_dispatched);
};

} // namespace DPI

#endif // TRAFFIC_ORCHESTRATOR_H

