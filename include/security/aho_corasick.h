#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#include <string>
#include <vector>
#include <array>
#include <queue>
#include <cstdint>
#include <algorithm>
#include <cctype>

namespace DPI {

// ============================================================================
// Aho-Corasick Multi-Pattern Search Automaton
// Carrier-grade L7 deep packet payload inspection in O(N) linear time.
// Equivalent to Snort/Suricata multi-rule payload pattern matching.
// ============================================================================

struct PatternMatch {
    size_t pattern_id = 0;
    std::string name;
    std::string matched_string;
    size_t end_offset = 0;   // 1-based offset where match ends in payload
    size_t length = 0;
};

class AhoCorasick {
public:
    AhoCorasick(bool case_sensitive = false);

    // Register text keyword pattern (e.g. "UNION SELECT", "eval(base64_decode", "/bin/sh")
    void addPattern(const std::string& pattern,
                    const std::string& rule_name = "",
                    size_t pattern_id = 0);

    // Register raw binary pattern
    void addBinaryPattern(const std::vector<uint8_t>& pattern,
                          const std::string& rule_name = "",
                          size_t pattern_id = 0);

    // Build the failure transitions and dictionary output links (must call after adding all patterns)
    void build();

    // Fast wire-speed check: returns true on first match found (short-circuit for dropping packets)
    bool findFirst(const uint8_t* data, size_t length, PatternMatch* match_out = nullptr) const;

    // Search and return all matching patterns found across the payload
    std::vector<PatternMatch> searchAll(const uint8_t* data, size_t length) const;

    // Helper for std::string search
    bool findFirst(const std::string& text, PatternMatch* match_out = nullptr) const {
        return findFirst(reinterpret_cast<const uint8_t*>(text.data()), text.size(), match_out);
    }

    size_t patternCount() const { return patterns_.size(); }
    bool isBuilt() const { return built_; }
    void clear();

private:
    struct PatternEntry {
        size_t id = 0;
        std::string name;
        std::vector<uint8_t> bytes;
    };

    struct State {
        int next[256];
        int fail = 0;
        std::vector<size_t> output_indices; // Indices into patterns_

        State() {
            std::fill(std::begin(next), std::end(next), -1);
        }
    };

    bool case_sensitive_ = false;
    bool built_ = false;
    std::vector<PatternEntry> patterns_;
    std::vector<State> states_;

    uint8_t normalizeByte(uint8_t b) const {
        if (!case_sensitive_ && b >= 'A' && b <= 'Z') {
            return static_cast<uint8_t>(b + ('a' - 'A'));
        }
        return b;
    }
};

} // namespace DPI

#endif // AHO_CORASICK_H

