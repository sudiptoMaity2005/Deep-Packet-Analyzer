#include "traffic_shaper.h"
#include <iostream>
#include <algorithm>

namespace DPI {

std::string shaperAlgorithmToString(ShaperAlgorithm algo) {
    switch (algo) {
        case ShaperAlgorithm::NONE:         return "none";
        case ShaperAlgorithm::TOKEN_BUCKET: return "token-bucket";
        case ShaperAlgorithm::LEAKY_BUCKET: return "leaky-bucket";
        default:                            return "unknown";
    }
}

ShaperAlgorithm stringToShaperAlgorithm(const std::string& name) {
    std::string s = name;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (s == "none" || s == "passthrough" || s == "off") {
        return ShaperAlgorithm::NONE;
    }
    if (s == "leaky" || s == "leaky-bucket" || s == "leaky_bucket") {
        return ShaperAlgorithm::LEAKY_BUCKET;
    }
    if (s == "token" || s == "token-bucket" || s == "token_bucket") {
        return ShaperAlgorithm::TOKEN_BUCKET;
    }
    return ShaperAlgorithm::TOKEN_BUCKET;
}

TrafficShaper::TrafficShaper(const ShaperConfig& config) {
    configure(config);
}

void TrafficShaper::configure(const ShaperConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    tokens_ = config_.burst_capacity > 0.0 ? config_.burst_capacity : 1000.0;
    last_token_time_ = std::chrono::steady_clock::now();
    next_leaky_release_ = std::chrono::steady_clock::now();
}

void TrafficShaper::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    tokens_ = config_.burst_capacity > 0.0 ? config_.burst_capacity : 1000.0;
    last_token_time_ = std::chrono::steady_clock::now();
    next_leaky_release_ = std::chrono::steady_clock::now();
    total_admitted_ = 0;
    burst_packets_ = 0;
    delayed_packets_ = 0;
    high_priority_expedited_ = 0;
    total_delay_micros_ = 0;
}

bool TrafficShaper::isHighPriority(const PacketJob& job) const {
    if (!config_.enable_qos_priority) {
        return false;
    }

    // Expedite DNS queries and responses (UDP/TCP Port 53)
    if (job.tuple.src_port == 53 || job.tuple.dst_port == 53) {
        return true;
    }

    // Expedite TCP handshake and tear-down control packets: SYN, FIN, RST
    // TCP Protocol = 6
    if (job.tuple.protocol == 6) {
        // SYN (0x02), FIN (0x01), RST (0x04)
        if ((job.tcp_flags & (0x02 | 0x01 | 0x04)) != 0) {
            return true;
        }
    }

    return false;
}

double TrafficShaper::shape(const PacketJob& job) {
    // If shaping is disabled or unlimited
    if (config_.algorithm == ShaperAlgorithm::NONE ||
        (config_.rate_limit_pps <= 0.0 && config_.bandwidth_limit_mbps <= 0.0)) {
        total_admitted_++;
        return 0.0;
    }

    // QoS Expedited Forwarding: Handshakes and DNS bypass shaping latency
    if (isHighPriority(job)) {
        high_priority_expedited_++;
        total_admitted_++;
        return 0.0;
    }

    if (config_.algorithm == ShaperAlgorithm::TOKEN_BUCKET) {
        return shapeTokenBucket(job);
    } else if (config_.algorithm == ShaperAlgorithm::LEAKY_BUCKET) {
        return shapeLeakyBucket(job);
    }

    total_admitted_++;
    return 0.0;
}

double TrafficShaper::shapeTokenBucket(const PacketJob& job) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    double elapsed_sec = std::chrono::duration<double>(now - last_token_time_).count();

    double rate = config_.rate_limit_pps;
    double capacity = config_.burst_capacity > 0.0 ? config_.burst_capacity : 1000.0;

    // Check bandwidth-based mode if pps is 0
    double cost = 1.0;
    if (rate <= 0.0 && config_.bandwidth_limit_mbps > 0.0) {
        rate = (config_.bandwidth_limit_mbps * 1000000.0) / 8.0; // bytes per second
        cost = static_cast<double>(job.data.size());
        capacity = std::max(capacity, cost * 10.0);
    }

    // Replenish tokens based on elapsed wall-clock time
    tokens_ = std::min(capacity, tokens_ + elapsed_sec * rate);
    last_token_time_ = now;

    // If enough tokens exist, packet transmits without delay (absorbs burst)
    if (tokens_ >= cost) {
        tokens_ -= cost;
        burst_packets_++;
        total_admitted_++;
        return 0.0;
    }

    // Bucket depleted: calculate pacing wait time to accumulate required tokens
    double token_deficit = cost - tokens_;
    double wait_sec = (rate > 0.0) ? (token_deficit / rate) : 0.0;
    auto wait_micros = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::duration<double>(wait_sec)
    );

    // Consume the upcoming tokens and advance virtual clock
    tokens_ = 0.0;
    last_token_time_ = now + wait_micros;

    delayed_packets_++;
    total_delay_micros_ += wait_micros.count();
    total_admitted_++;

    lock.unlock();

    if (wait_micros.count() > 0) {
        std::this_thread::sleep_for(wait_micros);
    }

    return static_cast<double>(wait_micros.count());
}

double TrafficShaper::shapeLeakyBucket(const PacketJob& /*job*/) {
    std::unique_lock<std::mutex> lock(mutex_);

    double rate = config_.rate_limit_pps > 0.0 ? config_.rate_limit_pps : 1000.0;
    auto interval = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::duration<double>(1.0 / rate)
    );

    auto now = std::chrono::steady_clock::now();
    if (next_leaky_release_ < now) {
        next_leaky_release_ = now;
    }

    auto scheduled_release = next_leaky_release_;
    next_leaky_release_ += interval;

    auto wait_micros = std::chrono::duration_cast<std::chrono::microseconds>(
        scheduled_release - now
    );

    if (wait_micros.count() > 0) {
        delayed_packets_++;
        total_delay_micros_ += wait_micros.count();
    }
    total_admitted_++;

    lock.unlock();

    if (wait_micros.count() > 0) {
        std::this_thread::sleep_for(wait_micros);
        return static_cast<double>(wait_micros.count());
    }

    return 0.0;
}

bool TrafficShaper::canAdmitImmediately(const PacketJob& job) {
    if (config_.algorithm == ShaperAlgorithm::NONE ||
        (config_.rate_limit_pps <= 0.0 && config_.bandwidth_limit_mbps <= 0.0)) {
        return true;
    }

    if (isHighPriority(job)) {
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    if (config_.algorithm == ShaperAlgorithm::TOKEN_BUCKET) {
        double elapsed_sec = std::chrono::duration<double>(now - last_token_time_).count();
        double rate = config_.rate_limit_pps;
        double capacity = config_.burst_capacity > 0.0 ? config_.burst_capacity : 1000.0;
        double cost = 1.0;

        if (rate <= 0.0 && config_.bandwidth_limit_mbps > 0.0) {
            rate = (config_.bandwidth_limit_mbps * 1000000.0) / 8.0;
            cost = static_cast<double>(job.data.size());
            capacity = std::max(capacity, cost * 10.0);
        }

        double virtual_tokens = std::min(capacity, tokens_ + elapsed_sec * rate);
        return virtual_tokens >= cost;
    } else if (config_.algorithm == ShaperAlgorithm::LEAKY_BUCKET) {
        return now >= next_leaky_release_;
    }

    return true;
}

ShaperStats TrafficShaper::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ShaperStats stats;
    stats.total_admitted = total_admitted_.load();
    stats.burst_packets = burst_packets_.load();
    stats.delayed_packets = delayed_packets_.load();
    stats.high_priority_expedited = high_priority_expedited_.load();
    stats.total_delay_seconds = static_cast<double>(total_delay_micros_.load()) / 1e6;
    stats.current_tokens = tokens_;
    stats.sustained_rate_pps = config_.rate_limit_pps;
    return stats;
}

} // namespace DPI

