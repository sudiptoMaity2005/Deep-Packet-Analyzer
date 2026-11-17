#include "security/aho_corasick.h"

namespace DPI {

AhoCorasick::AhoCorasick(bool case_sensitive)
    : case_sensitive_(case_sensitive) {
    clear();
}

void AhoCorasick::clear() {
    patterns_.clear();
    states_.clear();
    states_.emplace_back(); // Root state = 0
    built_ = false;
}

void AhoCorasick::addPattern(const std::string& pattern,
                             const std::string& rule_name,
                             size_t pattern_id) {
    if (pattern.empty()) return;
    std::vector<uint8_t> bytes(pattern.begin(), pattern.end());
    addBinaryPattern(bytes, rule_name.empty() ? pattern : rule_name, pattern_id);
}

void AhoCorasick::addBinaryPattern(const std::vector<uint8_t>& pattern,
                                   const std::string& rule_name,
                                   size_t pattern_id) {
    if (pattern.empty()) return;

    size_t entry_idx = patterns_.size();
    PatternEntry entry;
    entry.id = pattern_id == 0 ? (entry_idx + 1) : pattern_id;
    entry.name = rule_name.empty() ? ("rule_" + std::to_string(entry.id)) : rule_name;
    entry.bytes = pattern;
    patterns_.push_back(entry);

    int curr = 0;
    for (uint8_t raw_b : pattern) {
        uint8_t b = normalizeByte(raw_b);
        if (states_[curr].next[b] == -1) {
            int next_state = static_cast<int>(states_.size());
            states_.emplace_back();
            states_[curr].next[b] = next_state;
        }
        curr = states_[curr].next[b];
    }

    states_[curr].output_indices.push_back(entry_idx);
    built_ = false;
}

void AhoCorasick::build() {
    if (states_.empty()) return;

    std::queue<int> q;

    // Direct transitions from root (depth 1)
    for (int c = 0; c < 256; ++c) {
        if (states_[0].next[c] != -1) {
            int child = states_[0].next[c];
            states_[child].fail = 0;
            q.push(child);
        } else {
            states_[0].next[c] = 0; // Self-loop on root for unmatched characters
        }
    }

    // BFS compute failure links and dictionary output links
    while (!q.empty()) {
        int u = q.front();
        q.pop();

        for (int c = 0; c < 256; ++c) {
            if (states_[u].next[c] != -1) {
                int v = states_[u].next[c];
                int f = states_[u].fail;

                while (states_[f].next[c] == -1) {
                    f = states_[f].fail;
                }

                states_[v].fail = states_[f].next[c];

                // Merge dictionary outputs from failure state (suffix links)
                const auto& fail_outputs = states_[states_[v].fail].output_indices;
                states_[v].output_indices.insert(
                    states_[v].output_indices.end(),
                    fail_outputs.begin(),
                    fail_outputs.end()
                );

                q.push(v);
            }
        }
    }

    built_ = true;
}

bool AhoCorasick::findFirst(const uint8_t* data, size_t length, PatternMatch* match_out) const {
    if (!built_ || states_.empty() || patterns_.empty() || data == nullptr || length == 0) {
        return false;
    }

    int curr = 0;

    for (size_t i = 0; i < length; ++i) {
        uint8_t c = normalizeByte(data[i]);

        while (states_[curr].next[c] == -1) {
            curr = states_[curr].fail;
        }

        curr = states_[curr].next[c];

        if (!states_[curr].output_indices.empty()) {
            if (match_out) {
                size_t p_idx = states_[curr].output_indices.front();
                match_out->pattern_id = patterns_[p_idx].id;
                match_out->name = patterns_[p_idx].name;
                match_out->matched_string = std::string(
                    patterns_[p_idx].bytes.begin(),
                    patterns_[p_idx].bytes.end()
                );
                match_out->length = patterns_[p_idx].bytes.size();
                match_out->end_offset = i + 1;
            }
            return true;
        }
    }

    return false;
}

std::vector<PatternMatch> AhoCorasick::searchAll(const uint8_t* data, size_t length) const {
    std::vector<PatternMatch> results;
    if (!built_ || states_.empty() || patterns_.empty() || data == nullptr || length == 0) {
        return results;
    }

    int curr = 0;

    for (size_t i = 0; i < length; ++i) {
        uint8_t c = normalizeByte(data[i]);

        while (states_[curr].next[c] == -1) {
            curr = states_[curr].fail;
        }

        curr = states_[curr].next[c];

        for (size_t p_idx : states_[curr].output_indices) {
            PatternMatch m;
            m.pattern_id = patterns_[p_idx].id;
            m.name = patterns_[p_idx].name;
            m.matched_string = std::string(
                patterns_[p_idx].bytes.begin(),
                patterns_[p_idx].bytes.end()
            );
            m.length = patterns_[p_idx].bytes.size();
            m.end_offset = i + 1;
            results.push_back(m);
        }
    }

    return results;
}

} // namespace DPI

