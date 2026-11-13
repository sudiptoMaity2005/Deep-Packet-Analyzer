#include "rule_manager.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>

namespace DPI {

// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    
    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static uint32_t makeCIDRMask(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFF;
    uint32_t mask = 0;
    for (int i = 0; i < prefix; i++) {
        int byte_idx = i / 8;
        int bit_in_byte = 7 - (i % 8);
        mask |= (1U << (byte_idx * 8 + bit_in_byte));
    }
    return mask;
}

void RuleManager::blockCIDR(const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        blockIP(cidr);
        return;
    }
    std::string ip_part = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    uint32_t net = parseIP(ip_part);
    uint32_t mask = makeCIDRMask(prefix);
    
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_cidrs_.push_back({net, mask, cidr});
    std::cout << "[RuleManager] Blocked CIDR subnet: " << cidr << std::endl;
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
    std::cout << "[RuleManager] Blocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::blockIP(const std::string& ip) {
    if (ip.find('/') != std::string::npos) {
        blockCIDR(ip);
    } else {
        blockIP(parseIP(ip));
    }
}

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
    std::cout << "[RuleManager] Unblocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::unblockIP(const std::string& ip) {
    if (ip.find('/') != std::string::npos) {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);
        blocked_cidrs_.erase(
            std::remove_if(blocked_cidrs_.begin(), blocked_cidrs_.end(),
                           [&](const CIDRBlock& c) { return c.cidr_str == ip; }),
            blocked_cidrs_.end());
        std::cout << "[RuleManager] Unblocked CIDR subnet: " << ip << std::endl;
    } else {
        unblockIP(parseIP(ip));
    }
}

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    if (blocked_ips_.count(ip) > 0) return true;
    for (const auto& cidr : blocked_cidrs_) {
        if ((ip & cidr.mask) == (cidr.network & cidr.mask)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) {
        result.push_back(ipToString(ip));
    }
    for (const auto& cidr : blocked_cidrs_) {
        result.push_back(cidr.cidr_str);
    }
    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
    std::cout << "[RuleManager] Blocked app: " << appTypeToString(app) << std::endl;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
    std::cout << "[RuleManager] Unblocked app: " << appTypeToString(app) << std::endl;
}

bool RuleManager::isAppBlocked(AppType app) const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return blocked_apps_.count(app) > 0;
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        domain_patterns_.push_back(domain);
    } else {
        blocked_domains_.insert(domain);
    }
    
    std::cout << "[RuleManager] Blocked domain: " << domain << std::endl;
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        auto it = std::find(domain_patterns_.begin(), domain_patterns_.end(), domain);
        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }
    } else {
        blocked_domains_.erase(domain);
    }
    
    std::cout << "[RuleManager] Unblocked domain: " << domain << std::endl;
}

bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1);  // .example.com
        
        // Check if domain ends with the pattern
        if (domain.size() >= suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        
        // Also match the bare domain (example.com matches *.example.com)
        if (domain == pattern.substr(2)) {
            return true;
        }
    }
    
    return false;
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    
    // Check exact match
    if (blocked_domains_.count(domain) > 0) {
        return true;
    }
    
    // Check patterns
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    for (const auto& pattern : domain_patterns_) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
        if (domainMatchesPattern(lower_domain, lower_pattern)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Blocked port: " << port << std::endl;
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// L7 Payload Signature Blocking (Aho-Corasick)
// ============================================================================

void RuleManager::blockPayloadSignature(const std::string& signature, const std::string& rule_name) {
    std::unique_lock<std::shared_mutex> lock(payload_mutex_);
    std::string name = rule_name.empty() ? signature : rule_name;
    payload_matcher_.addPattern(signature, name);
    payload_matcher_.build();
    blocked_signatures_.push_back(name);
    std::cout << "[RuleManager] Blocked payload signature: " << name << " (\"" << signature << "\")\n";
}

void RuleManager::blockPayloadBinary(const std::vector<uint8_t>& pattern, const std::string& rule_name) {
    std::unique_lock<std::shared_mutex> lock(payload_mutex_);
    payload_matcher_.addBinaryPattern(pattern, rule_name);
    payload_matcher_.build();
    blocked_signatures_.push_back(rule_name);
    std::cout << "[RuleManager] Blocked binary payload signature: " << rule_name << " (" << pattern.size() << " bytes)\n";
}

void RuleManager::loadDefaultNIDSSignatures() {
    std::unique_lock<std::shared_mutex> lock(payload_mutex_);
    // SQL Injection patterns
    payload_matcher_.addPattern("UNION SELECT", "SQLi_UNION_SELECT");
    payload_matcher_.addPattern("UNION ALL SELECT", "SQLi_UNION_ALL_SELECT");
    payload_matcher_.addPattern("' OR '1'='1", "SQLi_AUTH_BYPASS");
    payload_matcher_.addPattern("SLEEP(", "SQLi_TIME_BASED");
    
    // Command Injection & Remote Shells
    payload_matcher_.addPattern("/bin/sh", "RCE_UNIX_SHELL");
    payload_matcher_.addPattern("/bin/bash", "RCE_BASH_SHELL");
    payload_matcher_.addPattern("cmd.exe", "RCE_WIN_CMD");
    payload_matcher_.addPattern("powershell.exe", "RCE_WIN_POWERSHELL");
    
    // Web Shells & PHP execution
    payload_matcher_.addPattern("eval(base64_decode", "WEBSHELL_EVAL_BASE64");
    payload_matcher_.addPattern("<?php system(", "WEBSHELL_PHP_SYSTEM");
    payload_matcher_.addPattern("passthru(", "WEBSHELL_PHP_PASSTHRU");
    
    // Directory Traversal
    payload_matcher_.addPattern("/etc/passwd", "PATH_TRAVERSAL_PASSWD");
    payload_matcher_.addPattern("..\\..\\windows", "PATH_TRAVERSAL_WIN");

    payload_matcher_.build();

    blocked_signatures_.push_back("NIDS_SQLI_SUITE");
    blocked_signatures_.push_back("NIDS_RCE_SUITE");
    blocked_signatures_.push_back("NIDS_WEBSHELL_SUITE");
    blocked_signatures_.push_back("NIDS_TRAVERSAL_SUITE");

    std::cout << "[RuleManager] Loaded " << payload_matcher_.patternCount()
              << " default NIDS attack signatures (SQLi, RCE, Webshells, Traversal)\n";
}

bool RuleManager::isPayloadBlocked(const uint8_t* payload, size_t length, std::string* matched_rule_out) const {
    std::shared_lock<std::shared_mutex> lock(payload_mutex_);
    if (!payload_matcher_.isBuilt() || payload_matcher_.patternCount() == 0 ||
        payload == nullptr || length == 0) {
        return false;
    }

    PatternMatch match;
    if (payload_matcher_.findFirst(payload, length, &match)) {
        if (matched_rule_out) {
            *matched_rule_out = match.name + " [offset " + std::to_string(match.end_offset) + "]";
        }
        return true;
    }
    return false;
}

std::vector<std::string> RuleManager::getBlockedSignatures() const {
    std::shared_lock<std::shared_mutex> lock(payload_mutex_);
    return blocked_signatures_;
}

// ============================================================================
// Security Anomaly Detection (DGA & DNS Tunneling)
// ============================================================================

void RuleManager::enableSecurityAnomalyDetection(bool enable) {
    security_anomaly_enabled_ = enable;
    std::cout << "[RuleManager] Security Intelligence & Anomaly Detection "
              << (enable ? "ENABLED" : "DISABLED") << "\n";
}

bool RuleManager::isSecurityAnomalyDetectionEnabled() const {
    return security_anomaly_enabled_.load();
}

void RuleManager::setDGAEntropyThreshold(double threshold) {
    security_analyzer_.setDGAThreshold(threshold);
}

double RuleManager::getDGAEntropyThreshold() const {
    return security_analyzer_.getDGAThreshold();
}

// ============================================================================
// Per-Flow Micro-Token Bucket Bandwidth Quotas
// ============================================================================

void RuleManager::setDefaultFlowRateLimit(double bytes_per_sec, double burst_bytes) {
    std::unique_lock<std::shared_mutex> lock(flow_policy_mutex_);
    default_flow_rate_bps_ = bytes_per_sec;
    default_flow_burst_bytes_ = burst_bytes;
    has_flow_limits_ = (bytes_per_sec > 0.0 || !app_flow_rate_limits_.empty());
    std::cout << "[RuleManager] Default flow rate limit set to: "
              << (bytes_per_sec / 1024.0) << " KB/s (Burst: "
              << (burst_bytes / 1024.0) << " KB)\n";
}

void RuleManager::setAppFlowRateLimit(AppType app, double bytes_per_sec, double burst_bytes) {
    std::unique_lock<std::shared_mutex> lock(flow_policy_mutex_);
    app_flow_rate_limits_[app] = {bytes_per_sec, burst_bytes};
    has_flow_limits_ = true;
    std::cout << "[RuleManager] App " << appTypeToString(app)
              << " flow rate limit set to: " << (bytes_per_sec / 1024.0)
              << " KB/s (Burst: " << (burst_bytes / 1024.0) << " KB)\n";
}

bool RuleManager::hasFlowRateLimits() const {
    return has_flow_limits_.load();
}

void RuleManager::applyFlowPolicy(Connection* conn) const {
    if (!conn || !has_flow_limits_.load()) return;

    std::shared_lock<std::shared_mutex> lock(flow_policy_mutex_);
    auto it = app_flow_rate_limits_.find(conn->app_type);
    if (it != app_flow_rate_limits_.end()) {
        conn->flow_bucket.configure(it->second.first, it->second.second);
    } else if (default_flow_rate_bps_ > 0.0) {
        conn->flow_bucket.configure(default_flow_rate_bps_, default_flow_burst_bytes_);
    }
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain,
    const uint8_t* payload_data,
    size_t payload_length) const {
    
    // Check IP first (most specific)
    if (isIPBlocked(src_ip)) {
        return BlockReason{BlockReason::Type::IP, ipToString(src_ip)};
    }
    
    // Check port
    if (isPortBlocked(dst_port)) {
        return BlockReason{BlockReason::Type::PORT, std::to_string(dst_port)};
    }
    
    // Check app
    if (isAppBlocked(app)) {
        return BlockReason{BlockReason::Type::APP, appTypeToString(app)};
    }
    
    // Check domain
    if (!domain.empty() && isDomainBlocked(domain)) {
        return BlockReason{BlockReason::Type::DOMAIN_NAME, domain};
    }

    // Check Layer-7 payload attack signatures using Aho-Corasick
    if (payload_data != nullptr && payload_length > 0) {
        std::string matched_sig;
        if (isPayloadBlocked(payload_data, payload_length, &matched_sig)) {
            return BlockReason{BlockReason::Type::PAYLOAD_SIGNATURE, matched_sig};
        }
    }

    // Check Security Anomaly (DGA C2 Beaconing & DNS Data Exfiltration Tunneling)
    if (security_anomaly_enabled_.load() && !domain.empty()) {
        auto dga = security_analyzer_.analyzeDomain(domain);
        if (dga.is_dga) {
            std::ostringstream ss;
            ss << "DGA Botnet Domain: " << domain << " (Entropy H="
               << std::fixed << std::setprecision(2) << dga.entropy << ") [" << dga.reason << "]";
            return BlockReason{BlockReason::Type::SECURITY_ANOMALY, ss.str()};
        }

        auto tunnel = security_analyzer_.analyzeDNSQuery(domain);
        if (tunnel.is_tunneling) {
            std::ostringstream ss;
            ss << "DNS Tunneling / Data Exfiltration: " << domain << " [" << tunnel.reason << "]";
            return BlockReason{BlockReason::Type::SECURITY_ANOMALY, ss.str()};
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// Persistence
// ============================================================================

bool RuleManager::saveRules(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    // Save blocked IPs
    file << "[BLOCKED_IPS]\n";
    for (const auto& ip : getBlockedIPs()) {
        file << ip << "\n";
    }
    
    // Save blocked apps
    file << "\n[BLOCKED_APPS]\n";
    for (const auto& app : getBlockedApps()) {
        file << appTypeToString(app) << "\n";
    }
    
    // Save blocked domains
    file << "\n[BLOCKED_DOMAINS]\n";
    for (const auto& domain : getBlockedDomains()) {
        file << domain << "\n";
    }
    
    // Save blocked ports
    file << "\n[BLOCKED_PORTS]\n";
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        for (uint16_t port : blocked_ports_) {
            file << port << "\n";
        }
    }
    
    file.close();
    std::cout << "[RuleManager] Rules saved to: " << filename << std::endl;
    return true;
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Check for section headers
        if (line[0] == '[') {
            current_section = line;
            continue;
        }
        
        // Process based on section
        if (current_section == "[BLOCKED_IPS]") {
            blockIP(line);
        } else if (current_section == "[BLOCKED_APPS]") {
            // Convert string back to AppType
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == line) {
                    blockApp(static_cast<AppType>(i));
                    break;
                }
            }
        } else if (current_section == "[BLOCKED_DOMAINS]") {
            blockDomain(line);
        } else if (current_section == "[BLOCKED_PORTS]") {
            blockPort(static_cast<uint16_t>(std::stoi(line)));
        }
    }
    
    file.close();
    std::cout << "[RuleManager] Rules loaded from: " << filename << std::endl;
    return true;
}

void RuleManager::clearAll() {
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);
        blocked_ips_.clear();
        blocked_cidrs_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);
        blocked_apps_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);
        blocked_domains_.clear();
        domain_patterns_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);
        blocked_ports_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(payload_mutex_);
        payload_matcher_.clear();
        blocked_signatures_.clear();
    }
    std::cout << "[RuleManager] All rules cleared" << std::endl;
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        stats.blocked_ips = blocked_ips_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);
        stats.blocked_apps = blocked_apps_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);
        stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        stats.blocked_ports = blocked_ports_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(payload_mutex_);
        stats.blocked_signatures = blocked_signatures_.size();
    }
    
    return stats;
}

} // namespace DPI
