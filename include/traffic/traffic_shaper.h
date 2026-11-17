#ifndef TRAFFIC_SHAPER_H
#define TRAFFIC_SHAPER_H

#include <cstdint>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <string>
#include "core/types.h"

namespace DPI {

// ============================================================================
// Traffic Shaper Algorithms
// ============================================================================
enum class ShaperAlgorithm {
    NONE,           // Direct passthrough, no rate limiting
    TOKEN_BUCKET,   // Allows bursts up to bucket capacity, limits sustained rate
    LEAKY_BUCKET    // Smooths out bursts to a strictly constant steady rate
};

std::string shaperAlgorithmToString(ShaperAlgorithm algo);
ShaperAlgorithm stringToShaperAlgorithm(const std::string& name);

// ============================================================================
// Traffic Shaper Configuration
// ============================================================================
struct ShaperConfig {
    ShaperAlgorithm algorithm = ShaperAlgorithm::TOKEN_BUCKET;
    double rate_limit_pps = 0.0;       // Packets per second (0 = unlimited)
    double burst_capacity = 1000.0;     // Max burst tolerance in tokens
    double bandwidth_limit_mbps = 0.0;  // Bandwidth limit in Mbps (0 = unlimited)
    bool enable_qos_priority = true;   // Expedite TCP handshake (SYN/FIN/RST) & DNS
};

// ============================================================================
// Traffic Shaper Statistics
// ============================================================================
struct ShaperStats {
    uint64_t total_admitted = 0;
    uint64_t burst_packets = 0;
    uint64_t delayed_packets = 0;
    uint64_t high_priority_expedited = 0;
    double total_delay_seconds = 0.0;
    double current_tokens = 0.0;
    double sustained_rate_pps = 0.0;
};

// ============================================================================
// Traffic Shaper
// Paces packets from abrupt traffic bursts into a steady, calibrated flow.
// ============================================================================
class TrafficShaper {
public:
    TrafficShaper(const ShaperConfig& config = ShaperConfig{});

    // Configure shaper parameters at runtime
    void configure(const ShaperConfig& config);
    const ShaperConfig& getConfig() const { return config_; }

    // Shape a packet: blocks the calling thread if pacing is needed
    // Returns delay time in microseconds
    double shape(const PacketJob& job);

    // Non-blocking check if packet can be admitted immediately
    bool canAdmitImmediately(const PacketJob& job);

    // Check if packet qualifies for high-priority expedited forwarding
    bool isHighPriority(const PacketJob& job) const;

    // Reset shaper state
    void reset();

    // Retrieve real-time shaping telemetry
    ShaperStats getStats() const;

private:
    ShaperConfig config_;
    mutable std::mutex mutex_;

    // Token Bucket State
    double tokens_;
    std::chrono::steady_clock::time_point last_token_time_;

    // Leaky Bucket State
    std::chrono::steady_clock::time_point next_leaky_release_;

    // Telemetry counters
    std::atomic<uint64_t> total_admitted_{0};
    std::atomic<uint64_t> burst_packets_{0};
    std::atomic<uint64_t> delayed_packets_{0};
    std::atomic<uint64_t> high_priority_expedited_{0};
    std::atomic<uint64_t> total_delay_micros_{0};

    // Helper routines
    double shapeTokenBucket(const PacketJob& job);
    double shapeLeakyBucket(const PacketJob& job);
};

} // namespace DPI

#endif // TRAFFIC_SHAPER_H

