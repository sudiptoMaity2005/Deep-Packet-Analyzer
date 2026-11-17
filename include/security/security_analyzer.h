#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include "core/types.h"

namespace DPI {

// ============================================================================
// Passive TCP Operating System Fingerprint (p0f style)
// ============================================================================
struct OSFingerprint {
    std::string os_family = "Unknown"; // "Linux / Android", "Windows", "macOS / iOS", "Network Equipment"
    uint8_t initial_ttl = 0;
    uint8_t estimated_hops = 0;
    uint16_t window_size = 0;
};

// ============================================================================
// DGA (Domain Generation Algorithm) Malware Analysis Result
// ============================================================================
struct DGAAnalysis {
    std::string domain;
    double entropy = 0.0;
    bool is_dga = false;
    std::string reason;
};

// ============================================================================
// DNS Tunneling & Data Exfiltration Analysis Result
// ============================================================================
struct DNSTunnelingAnalysis {
    std::string query_name;
    bool is_tunneling = false;
    double label_entropy = 0.0;
    size_t max_label_length = 0;
    double hex_or_b64_ratio = 0.0;
    std::string reason;
};

// ============================================================================
// Security Intelligence & Anomaly Analyzer
// Mathematical Shannon Entropy, DGA Classifier, DNS Tunneling Detector,
// and Passive OS Profiler.
// ============================================================================
class SecurityAnalyzer {
public:
    SecurityAnalyzer(double dga_entropy_threshold = 3.6);

    // Compute mathematical Shannon Entropy: H(S) = -sum(P(c) * log2(P(c)))
    static double calculateShannonEntropy(const std::string& str);

    // Extract Second-Level Domain (SLD) core excluding standard TLDs
    static std::string extractCoreDomain(const std::string& domain);

    // Detect algorithmic pseudo-random domains used by C2 botnets / malware
    DGAAnalysis analyzeDomain(const std::string& domain) const;

    // Detect DNS data exfiltration / covert tunneling attempts
    DNSTunnelingAnalysis analyzeDNSQuery(const std::string& dns_query) const;

    // Passively infer client OS from TCP SYN packet parameters
    static OSFingerprint fingerprintTCPSYN(uint8_t captured_ttl,
                                           uint16_t window_size,
                                           uint8_t tcp_flags);

    void setDGAThreshold(double threshold) { dga_threshold_ = threshold; }
    double getDGAThreshold() const { return dga_threshold_; }

private:
    double dga_threshold_ = 3.6;
};

} // namespace DPI

#endif // SECURITY_ANALYZER_H

