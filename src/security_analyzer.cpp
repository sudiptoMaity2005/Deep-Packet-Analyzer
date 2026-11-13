#include "security_analyzer.h"
#include <sstream>
#include <array>
#include <iomanip>

namespace DPI {

SecurityAnalyzer::SecurityAnalyzer(double dga_entropy_threshold)
    : dga_threshold_(dga_entropy_threshold) {
}

double SecurityAnalyzer::calculateShannonEntropy(const std::string& str) {
    if (str.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (unsigned char c : str) {
        freq[c]++;
    }

    double entropy = 0.0;
    double len = static_cast<double>(str.size());
    double log2_const = std::log(2.0);

    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / len;
            entropy -= p * (std::log(p) / log2_const);
        }
    }

    return entropy;
}

std::string SecurityAnalyzer::extractCoreDomain(const std::string& domain) {
    std::string s = domain;
    // Lowercase
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    // Strip trailing dots
    while (!s.empty() && s.back() == '.') {
        s.pop_back();
    }

    // Strip common leading prefixes
    const std::vector<std::string> prefixes = {"www.", "api.", "m.", "mobile.", "static."};
    for (const auto& p : prefixes) {
        if (s.rfind(p, 0) == 0 && s.size() > p.size()) {
            s = s.substr(p.size());
            break;
        }
    }

    // Split by '.'
    std::vector<std::string> labels;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, '.')) {
        if (!token.empty()) {
            labels.push_back(token);
        }
    }

    if (labels.empty()) return domain;
    if (labels.size() == 1) return labels[0];

    // Common TLDs
    const std::vector<std::string> tlds = {
        "com", "net", "org", "edu", "gov", "mil", "io", "biz", "info", "co", "me",
        "ru", "cn", "de", "uk", "jp", "fr", "au", "br", "in", "app", "dev", "ai"
    };

    // If second to last is a 2-letter ccTLD (like co.uk), strip both
    if (labels.size() >= 3) {
        if (labels.back().size() == 2 && labels[labels.size() - 2].size() <= 3) {
            return labels[labels.size() - 3];
        }
    }

    // Return the label immediately preceding the TLD
    return labels[labels.size() - 2];
}

DGAAnalysis SecurityAnalyzer::analyzeDomain(const std::string& domain) const {
    DGAAnalysis res;
    res.domain = domain;
    std::string core = extractCoreDomain(domain);
    res.entropy = calculateShannonEntropy(core);

    // DGA detection heuristics:
    // 1. Core length >= 8
    // 2. High Shannon entropy (typically >= threshold, default 3.6)
    // 3. High ratio of digits or rare consonants
    if (core.size() >= 8 && res.entropy >= dga_threshold_) {
        res.is_dga = true;
        std::stringstream ss;
        ss << "DGA detected in core '" << core << "': Shannon Entropy "
           << std::fixed << std::setprecision(2) << res.entropy
           << " >= " << dga_threshold_ << " threshold";
        res.reason = ss.str();
    } else {
        res.is_dga = false;
    }

    return res;
}

DNSTunnelingAnalysis SecurityAnalyzer::analyzeDNSQuery(const std::string& dns_query) const {
    DNSTunnelingAnalysis res;
    res.query_name = dns_query;

    std::stringstream ss(dns_query);
    std::string label;
    std::string longest_label;

    while (std::getline(ss, label, '.')) {
        if (label.size() > longest_label.size()) {
            longest_label = label;
        }
    }

    res.max_label_length = longest_label.size();
    res.label_entropy = calculateShannonEntropy(longest_label);

    if (longest_label.empty()) {
        return res;
    }

    size_t hex_count = 0;
    size_t b64_count = 0;

    for (unsigned char c : longest_label) {
        if (std::isxdigit(c)) hex_count++;
        if (std::isalnum(c) || c == '-' || c == '_' || c == '+' || c == '/' || c == '=') {
            b64_count++;
        }
    }

    double len = static_cast<double>(longest_label.size());
    double hex_ratio = static_cast<double>(hex_count) / len;
    double b64_ratio = static_cast<double>(b64_count) / len;
    res.hex_or_b64_ratio = std::max(hex_ratio, b64_ratio);

    // DNS Tunneling heuristics:
    // Data exfiltration packets hide encoded payloads in labels:
    // - Abnormally long label (>= 32 chars) with high hex/b64 ratio >= 90%
    // - Abnormally high entropy (>= 3.5) with label length >= 28
    if ((res.max_label_length >= 32 && res.hex_or_b64_ratio >= 0.90) ||
        (res.max_label_length >= 28 && res.label_entropy >= 3.5)) {
        res.is_tunneling = true;
        std::stringstream r_ss;
        r_ss << "DNS Tunneling exfiltration detected: label length "
             << res.max_label_length << ", entropy "
             << std::fixed << std::setprecision(2) << res.label_entropy
             << ", encoded ratio " << (res.hex_or_b64_ratio * 100.0) << "%";
        res.reason = r_ss.str();
    } else {
        res.is_tunneling = false;
    }

    return res;
}

OSFingerprint SecurityAnalyzer::fingerprintTCPSYN(uint8_t captured_ttl,
                                                  uint16_t window_size,
                                                  uint8_t tcp_flags) {
    OSFingerprint fp;
    fp.window_size = window_size;

    // Only inspect TCP SYN packets
    if ((tcp_flags & 0x02) == 0) {
        fp.os_family = "Unknown (Non-SYN)";
        return fp;
    }

    // Determine initial TTL by rounding up to standard powers/hops
    if (captured_ttl <= 64) {
        fp.initial_ttl = 64;
        fp.estimated_hops = 64 - captured_ttl;

        if (window_size == 65535) {
            fp.os_family = "macOS / iOS";
        } else if (window_size == 29200 || window_size == 64240 ||
                   window_size == 14600 || (window_size > 0 && window_size % 1460 == 0)) {
            fp.os_family = "Linux / Android";
        } else {
            fp.os_family = "Linux / Android";
        }
    } else if (captured_ttl <= 128) {
        fp.initial_ttl = 128;
        fp.estimated_hops = 128 - captured_ttl;
        fp.os_family = "Windows";
    } else {
        fp.initial_ttl = 255;
        fp.estimated_hops = 255 - captured_ttl;
        fp.os_family = "Network Equipment / BSD";
    }

    return fp;
}

} // namespace DPI
