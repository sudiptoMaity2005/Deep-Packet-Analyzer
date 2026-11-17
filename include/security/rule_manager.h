#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "core/types.h"
#include "security/aho_corasick.h"
#include "security/security_analyzer.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <vector>
#include <fstream>

namespace DPI {

// ============================================================================
// Rule Manager - Manages blocking/filtering rules
// ============================================================================
// 
// Rules can be:
// 1. IP-based: Block specific source IPs
// 2. App-based: Block specific applications (detected via SNI)
// 3. Domain-based: Block specific domains
// 4. Port-based: Block specific destination ports
//
// Rules are thread-safe for concurrent access from FP threads
// ============================================================================

class RuleManager {
public:
    RuleManager() = default;
    
    // ========== IP & Subnet Blocking ==========
    
    // Block a specific source IP or CIDR subnet (e.g. "192.168.1.100" or "192.168.1.0/24")
    void blockIP(uint32_t ip);
    void blockIP(const std::string& ip_or_cidr);
    void blockCIDR(const std::string& cidr);
    
    // Unblock an IP or CIDR
    void unblockIP(uint32_t ip);
    void unblockIP(const std::string& ip_or_cidr);
    
    // Check if IP is blocked (by single IP or by any CIDR rule)
    bool isIPBlocked(uint32_t ip) const;
    
    // Get list of blocked IPs and CIDRs (for display)
    std::vector<std::string> getBlockedIPs() const;
    
    // ========== Application Blocking ==========
    
    // Block a specific application type
    void blockApp(AppType app);
    
    // Unblock an application
    void unblockApp(AppType app);
    
    // Check if app is blocked
    bool isAppBlocked(AppType app) const;
    
    // Get list of blocked apps
    std::vector<AppType> getBlockedApps() const;
    
    // ========== Domain Blocking ==========
    
    // Block a specific domain (or pattern)
    // Supports wildcards: *.facebook.com blocks all facebook subdomains
    void blockDomain(const std::string& domain);
    
    // Unblock a domain
    void unblockDomain(const std::string& domain);
    
    // Check if domain matches any block rule
    bool isDomainBlocked(const std::string& domain) const;
    
    // Get list of blocked domains
    std::vector<std::string> getBlockedDomains() const;
    
    // ========== Port Blocking ==========
    
    // Block a specific destination port
    void blockPort(uint16_t port);
    
    // Unblock a port
    void unblockPort(uint16_t port);
    
    // Check if port is blocked
    bool isPortBlocked(uint16_t port) const;
    
    // ========== L7 Payload Signature Blocking (Aho-Corasick) ==========
    
    // Block payloads matching a textual signature (e.g. "UNION SELECT", "/bin/sh")
    void blockPayloadSignature(const std::string& signature, const std::string& rule_name = "");
    
    // Block payloads matching a raw binary pattern
    void blockPayloadBinary(const std::vector<uint8_t>& pattern, const std::string& rule_name = "");
    
    // Load pre-configured NIDS signatures (SQLi, RCE, Webshells, Beacons)
    void loadDefaultNIDSSignatures();
    
    // Check if payload matches any blocked signature in O(N) linear time
    bool isPayloadBlocked(const uint8_t* payload, size_t length, std::string* matched_rule_out = nullptr) const;
    
    // Get list of registered payload signatures
    std::vector<std::string> getBlockedSignatures() const;

    // ========== Security Anomaly Detection (DGA & DNS Tunneling) ==========
    void enableSecurityAnomalyDetection(bool enable = true);
    bool isSecurityAnomalyDetectionEnabled() const;
    void setDGAEntropyThreshold(double threshold);
    double getDGAEntropyThreshold() const;

    // ========== Per-Flow Micro-Token Bucket Bandwidth Quotas ==========
    void setDefaultFlowRateLimit(double bytes_per_sec, double burst_bytes = 65536.0);
    void setAppFlowRateLimit(AppType app, double bytes_per_sec, double burst_bytes = 65536.0);
    void applyFlowPolicy(Connection* conn) const;
    bool hasFlowRateLimits() const;

    // ========== Combined Check ==========
    
    // Check if a packet/connection should be blocked based on all rules
    // Returns the reason if blocked, nullopt if allowed
    struct BlockReason {
        enum class Type : uint8_t { IP, APP, DOMAIN_NAME, PORT, PAYLOAD_SIGNATURE, SECURITY_ANOMALY, RATE_LIMIT } type;
        std::string detail;
    };
    
    std::optional<BlockReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain,
        const uint8_t* payload_data = nullptr,
        size_t payload_length = 0) const;
    
    // ========== Rule Persistence ==========
    
    // Save rules to file
    bool saveRules(const std::string& filename) const;
    
    // Load rules from file
    bool loadRules(const std::string& filename);
    
    // Clear all rules
    void clearAll();
    
    // ========== Statistics ==========
    
    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
        size_t blocked_signatures;
    };
    
    RuleStats getStats() const;

private:
    // Thread-safe containers with read-write locks
    struct CIDRBlock {
        uint32_t network = 0;
        uint32_t mask = 0;
        std::string cidr_str;
    };
    
    mutable std::shared_mutex ip_mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::vector<CIDRBlock> blocked_cidrs_;
    
    mutable std::shared_mutex app_mutex_;
    std::unordered_set<AppType> blocked_apps_;
    
    mutable std::shared_mutex domain_mutex_;
    std::unordered_set<std::string> blocked_domains_;
    std::vector<std::string> domain_patterns_;  // For wildcard matching
    
    mutable std::shared_mutex port_mutex_;
    std::unordered_set<uint16_t> blocked_ports_;
    
    mutable std::shared_mutex payload_mutex_;
    AhoCorasick payload_matcher_{false}; // Case-insensitive L7 signature matcher
    std::vector<std::string> blocked_signatures_;
    
    std::atomic<bool> security_anomaly_enabled_{false};
    SecurityAnalyzer security_analyzer_;

    mutable std::shared_mutex flow_policy_mutex_;
    std::atomic<bool> has_flow_limits_{false};
    double default_flow_rate_bps_ = 0.0;
    double default_flow_burst_bytes_ = 65536.0;
    std::unordered_map<AppType, std::pair<double, double>> app_flow_rate_limits_;
    
    // Helper: Convert IP string to uint32
    static uint32_t parseIP(const std::string& ip);
    
    // Helper: Convert uint32 to IP string
    static std::string ipToString(uint32_t ip);
    
    // Helper: Check if domain matches pattern (supports wildcards)
    static bool domainMatchesPattern(const std::string& domain, const std::string& pattern);
};

} // namespace DPI

#endif // RULE_MANAGER_H
