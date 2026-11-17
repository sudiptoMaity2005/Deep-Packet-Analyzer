#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <array>
#include <atomic>
#include <optional>

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow (supports IPv4 & IPv6)
// ============================================================================
struct FiveTuple {
    uint8_t  ip_version = 4; // 4 for IPv4, 6 for IPv6
    uint32_t src_ip = 0;     // For IPv4
    uint32_t dst_ip = 0;     // For IPv4
    std::array<uint8_t, 16> src_ip6{}; // For IPv6
    std::array<uint8_t, 16> dst_ip6{}; // For IPv6
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;   // TCP=6, UDP=17
    
    bool operator==(const FiveTuple& other) const {
        if (ip_version != other.ip_version ||
            src_port != other.src_port ||
            dst_port != other.dst_port ||
            protocol != other.protocol) {
            return false;
        }
        if (ip_version == 4) {
            return src_ip == other.src_ip && dst_ip == other.dst_ip;
        } else {
            return src_ip6 == other.src_ip6 && dst_ip6 == other.dst_ip6;
        }
    }
    
    // Create reverse tuple (for matching bidirectional flows)
    FiveTuple reverse() const {
        FiveTuple rev = *this;
        rev.src_port = dst_port;
        rev.dst_port = src_port;
        if (ip_version == 4) {
            rev.src_ip = dst_ip;
            rev.dst_ip = src_ip;
        } else {
            rev.src_ip6 = dst_ip6;
            rev.dst_ip6 = src_ip6;
        }
        return rev;
    }
    
    std::string toString() const;
};

// Symmetric Hash function for FiveTuple (ensures A->B and B->A hash to the same value)
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple, uint64_t seed = 0) const {
        uint64_t h = 14695981039346656037ULL ^ seed;
        auto mix = [&](uint64_t val) {
            h ^= val;
            h *= 1099511628211ULL;
        };

        if (tuple.ip_version == 4) {
            uint32_t ip1 = std::min(tuple.src_ip, tuple.dst_ip);
            uint32_t ip2 = std::max(tuple.src_ip, tuple.dst_ip);
            mix(ip1);
            mix(ip2);
        } else {
            // Symmetric mix of 16-byte IPv6 addresses
            bool src_smaller = tuple.src_ip6 < tuple.dst_ip6;
            const auto& a1 = src_smaller ? tuple.src_ip6 : tuple.dst_ip6;
            const auto& a2 = src_smaller ? tuple.dst_ip6 : tuple.src_ip6;
            for (size_t i = 0; i < 16; i += 4) {
                uint32_t w1 = (a1[i] << 24) | (a1[i+1] << 16) | (a1[i+2] << 8) | a1[i+3];
                uint32_t w2 = (a2[i] << 24) | (a2[i+1] << 16) | (a2[i+2] << 8) | a2[i+3];
                mix(w1);
                mix(w2);
            }
        }

        uint16_t p1 = std::min(tuple.src_port, tuple.dst_port);
        uint16_t p2 = std::max(tuple.src_port, tuple.dst_port);
        mix((static_cast<uint64_t>(p1) << 16) | p2);
        mix(tuple.protocol);

        // MurmurHash3 64-bit finalizer
        h ^= (h >> 33);
        h *= 0xff51afd7ed558ccdULL;
        h ^= (h >> 33);
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= (h >> 33);

        return static_cast<size_t>(h);
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications (detected via SNI/Host/DNS)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    // Modern AI & Cloud/Social Platforms
    CHATGPT,
    CLAUDE,
    REDDIT,
    LINKEDIN,
    TWITCH,
    SLACK,
    // Add more as needed
    APP_COUNT  // Keep this last for counting
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================
enum class PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
};

// ============================================================================
// Lock-free Micro-Token Bucket for Per-Flow Bandwidth Shaping
// Because packets belonging to the same flow are always routed to the same
// Fast-Path thread via consistent hashing, each flow's micro token bucket
// is strictly single-threaded, requiring ZERO atomic operations or locks.
// ============================================================================
struct MicroTokenBucket {
    double rate_bps = 0.0;           // Bytes per second (0.0 = unlimited)
    double burst_capacity = 65536.0; // Max burst in bytes (default 64 KB)
    double tokens = 65536.0;         // Current token balance (in bytes)
    std::chrono::steady_clock::time_point last_update = std::chrono::steady_clock::now();

    void configure(double bytes_per_sec, double burst_bytes = 65536.0) {
        rate_bps = bytes_per_sec;
        burst_capacity = burst_bytes;
        tokens = std::min(tokens, burst_capacity);
    }

    // Try to consume 'bytes_needed' tokens. Returns true if allowed, false if rate-limited.
    bool consume(size_t bytes_needed, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
        if (rate_bps <= 0.0) {
            return true; // Unlimited
        }

        double elapsed_sec = std::chrono::duration<double>(now - last_update).count();
        last_update = now;

        // Refill tokens
        tokens = std::min(burst_capacity, tokens + elapsed_sec * rate_bps);

        if (tokens >= static_cast<double>(bytes_needed)) {
            tokens -= static_cast<double>(bytes_needed);
            return true;
        }

        return false; // Quota exceeded!
    }
};

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================
struct Connection {
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;  // Server Name Indication (if detected)
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action = PacketAction::FORWARD;
    
    // For TCP state tracking
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;

    // Security Intelligence & Fingerprinting
    std::string inferred_os = "Unknown";
    double domain_entropy = 0.0;
    bool is_dga_anomaly = false;
    bool is_dns_tunneling = false;

    // Per-Flow Micro-Token Bucket Bandwidth Quota
    MicroTokenBucket flow_bucket;
    uint64_t rate_limited_drops = 0;
};

// ============================================================================
// Packet wrapper for queue passing
// ============================================================================
struct PacketJob {
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    uint8_t ttl = 64;
    uint16_t window_size = 0;
    const uint8_t* payload_data = nullptr;
    
    // Timestamps
    uint32_t ts_sec;
    uint32_t ts_usec;
};

// ============================================================================
// Statistics - uses regular uint64_t, protected by mutex externally
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> rate_limited_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    // Non-copyable due to atomics
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
