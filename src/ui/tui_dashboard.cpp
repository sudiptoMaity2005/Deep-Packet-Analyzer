#include "ui/tui_dashboard.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

namespace DPI {

// ANSI Color Codes
namespace ANSI {
    constexpr const char* RESET       = "\033[0m";
    constexpr const char* BOLD        = "\033[1m";
    constexpr const char* DIM         = "\033[2m";
    constexpr const char* RED         = "\033[1;31m";
    constexpr const char* GREEN       = "\033[1;32m";
    constexpr const char* YELLOW      = "\033[1;33m";
    constexpr const char* CYAN        = "\033[1;36m";
    constexpr const char* WHITE       = "\033[1;37m";
    constexpr const char* BG_RED      = "\033[41;1;37m";
    constexpr const char* CLEAR_SCREEN = "\033[2J\033[H";
}

std::string TUIDashboard::renderProgressBar(double fraction, int width, const std::string& fill_color) {
    fraction = std::max(0.0, std::min(1.0, fraction));
    int filled = static_cast<int>(std::round(fraction * width));
    int empty = width - filled;

    std::string bar = fill_color;
    for (int i = 0; i < filled; ++i) bar += "█";
    bar += ANSI::DIM;
    for (int i = 0; i < empty; ++i) bar += "░";
    bar += ANSI::RESET;
    return bar;
}

std::string TUIDashboard::render(
    const DPIStats& stats,
    const LBManager* lb_mgr,
    const FPManager* fp_mgr,
    const GlobalConnectionTable* conn_table,
    const TrafficOrchestrator* orchestrator,
    const MultiQueueCaptureInterface* capture_interface,
    const RuleManager* rule_mgr,
    bool live_refresh
) {
    std::ostringstream ss;

    if (live_refresh) {
        ss << ANSI::CLEAR_SCREEN;
    }

    // =========================================================================
    // HEADER BANNER
    // =========================================================================
    ss << ANSI::CYAN << "╔══════════════════════════════════════════════════════════════════════════════════════╗\n"
       << "║ " << ANSI::WHITE << ANSI::BOLD << "         ⚡ DEEP PACKET ANALYZER — ENTERPRISE CYBER-OPS TUI DASHBOARD ⚡         " << ANSI::CYAN << "║\n"
       << "║ " << ANSI::CYAN << ANSI::DIM  << "                Multi-Core Load-Balanced DPI & NIDS Intelligence                " << ANSI::CYAN << "║\n"
       << "╠══════════════════════════════════════════════════════════════════════════════════════╣" << ANSI::RESET << "\n";

    // =========================================================================
    // INGESTION & NETWORK TELEMETRY
    // =========================================================================
    uint64_t total_pkts = stats.total_packets.load();
    uint64_t fwd_pkts = stats.forwarded_packets.load();
    uint64_t drop_pkts = stats.dropped_packets.load();
    uint64_t total_bytes = stats.total_bytes.load();
    double drop_pct = (total_pkts > 0) ? (100.0 * drop_pkts / total_pkts) : 0.0;

    double pps = 0.0;
    double mbps = 0.0;
    if (orchestrator) {
        auto ost = orchestrator->getStats();
        pps = ost.throughput_pps;
        mbps = ost.throughput_mbps;
    }

    ss << ANSI::CYAN << "║ " << ANSI::WHITE << ANSI::BOLD << "[ INGESTION & THROUGHPUT TELEMETRY ]" << ANSI::CYAN << std::string(50, ' ') << "║\n"
       << "║ " << ANSI::RESET << " Packets In:     " << ANSI::WHITE << ANSI::BOLD << std::setw(10) << total_pkts << ANSI::RESET
       << " | Throughput:   " << ANSI::GREEN << ANSI::BOLD << std::setw(8) << std::fixed << std::setprecision(1) << pps << " pps" << ANSI::RESET
       << " | Volume: " << ANSI::WHITE << std::setw(8) << std::fixed << std::setprecision(2) << (total_bytes / 1048576.0) << " MB" << ANSI::RESET
       << ANSI::CYAN << " ║\n"
       << "║ " << ANSI::RESET << " Forwarded:      " << ANSI::GREEN << std::setw(10) << fwd_pkts << ANSI::RESET
       << " | Bandwidth:    " << ANSI::CYAN << ANSI::BOLD << std::setw(8) << std::fixed << std::setprecision(2) << mbps << " Mbps" << ANSI::RESET
       << " | Protocol: " << ANSI::WHITE << stats.tcp_packets.load() << " TCP / " << stats.udp_packets.load() << " UDP" << ANSI::RESET
       << ANSI::CYAN << "   ║\n"
       << "║ " << ANSI::RESET << " Blocked/Drops:  "
       << (drop_pkts > 0 ? ANSI::RED : ANSI::GREEN) << std::setw(10) << drop_pkts << ANSI::RESET
       << " | Drop Rate:    " << (drop_pct > 0.0 ? ANSI::RED : ANSI::GREEN) << std::setw(7) << std::fixed << std::setprecision(2) << drop_pct << "%" << ANSI::RESET
       << "  | " << (drop_pct == 0.0 ? ANSI::GREEN : ANSI::YELLOW) << (drop_pct == 0.0 ? "● HEALTHY" : "▲ FILTERING") << ANSI::RESET
       << ANSI::CYAN << std::string(17, ' ') << "║\n"
       << "╠══════════════════════════════════════════════════════════════════════════════════════╣" << ANSI::RESET << "\n";

    // =========================================================================
    // MULTI-CORE WORKER LOAD DISTRIBUTION
    // =========================================================================
    ss << ANSI::CYAN << "║ " << ANSI::WHITE << ANSI::BOLD << "[ MULTI-CORE LOAD BALANCER & FAST PATH THREAD MATRIX ]" << ANSI::CYAN << std::string(32, ' ') << "║\n" << ANSI::RESET;

    if (lb_mgr && fp_mgr) {
        int num_lbs = lb_mgr->getNumLBs();
        int num_fps = fp_mgr->getNumFPs();

        for (int l = 0; l < num_lbs; ++l) {
            auto lb_st = lb_mgr->getLB(l).getStats();
            double lb_ratio = (total_pkts > 0) ? (static_cast<double>(lb_st.packets_dispatched) / total_pkts) : 0.0;
            std::string bar = renderProgressBar(lb_ratio, 16, ANSI::CYAN);

            ss << ANSI::CYAN << "║  " << ANSI::CYAN << ANSI::BOLD << "LB" << l << ANSI::RESET
               << " [" << bar << "] " << ANSI::WHITE << std::setw(5) << lb_st.packets_dispatched << " pkts"
               << " (" << std::setw(4) << std::fixed << std::setprecision(1) << (lb_ratio * 100.0) << "%)"
               << ANSI::DIM << " -> FPs: " << ANSI::RESET;

            // List child FPs
            for (int f = l * 2; f < std::min(num_fps, (l + 1) * 2); ++f) {
                auto fp_st = fp_mgr->getFP(f).getStats();
                ss << ANSI::WHITE << "FP" << f << ":" << fp_st.packets_processed
                   << (fp_st.packets_dropped > 0 ? (ANSI::RED + std::string("(-") + std::to_string(fp_st.packets_dropped) + ")") : "")
                   << ANSI::RESET << " ";
            }
            ss << ANSI::CYAN << " ║\n";
        }
    }

    ss << ANSI::CYAN << "╠══════════════════════════════════════════════════════════════════════════════════════╣" << ANSI::RESET << "\n";

    // =========================================================================
    // SECURITY INTELLIGENCE & THREAT RADAR
    // =========================================================================
    if (conn_table) {
        auto gstats = conn_table->getGlobalStats();

        ss << ANSI::CYAN << "║ " << ANSI::WHITE << ANSI::BOLD << "[ CYBER THREAT RADAR & ANOMALY DEFENSE ]" << ANSI::CYAN << std::string(46, ' ') << "║\n" << ANSI::RESET;

        if (gstats.total_dga_detected > 0 || gstats.total_dns_tunneling_detected > 0) {
            ss << ANSI::CYAN << "║  " << ANSI::BG_RED << " ALERT " << ANSI::RESET
               << " Threat Anomalies Flagged: "
               << ANSI::RED << ANSI::BOLD << (gstats.total_dga_detected + gstats.total_dns_tunneling_detected) << " malicious flows" << ANSI::RESET
               << ANSI::CYAN << std::string(31, ' ') << "║\n";

            for (const auto& [domain, entropy] : gstats.dga_alerts) {
                std::string d_display = (domain.length() > 32) ? (domain.substr(0, 29) + "...") : domain;
                ss << ANSI::CYAN << "║    " << ANSI::RED << "⚡ [DGA C2]" << ANSI::RESET
                   << " Domain: " << ANSI::WHITE << std::setw(32) << std::left << d_display << ANSI::RESET
                   << " | Shannon Entropy: " << ANSI::YELLOW << ANSI::BOLD << "H=" << std::fixed << std::setprecision(2) << entropy << ANSI::RESET
                   << ANSI::RED << " [BLOCKED]" << ANSI::RESET
                   << ANSI::CYAN << " ║\n";
            }

            for (const auto& tunnel : gstats.dns_tunneling_alerts) {
                std::string t_display = (tunnel.length() > 35) ? (tunnel.substr(0, 32) + "...") : tunnel;
                ss << ANSI::CYAN << "║    " << ANSI::RED << "⚠️ [DNS TUNNEL]" << ANSI::RESET
                   << " Exfiltration Query: " << ANSI::WHITE << std::setw(35) << std::left << t_display << ANSI::RESET
                   << ANSI::RED << " [BLOCKED]" << ANSI::RESET
                   << ANSI::CYAN << "       ║\n";
            }
        } else {
            ss << ANSI::CYAN << "║  " << ANSI::GREEN << "● SECURE" << ANSI::RESET
               << " Zero DGA C2 or DNS tunneling anomalies active across inspected flows"
               << ANSI::CYAN << "       ║\n";
        }

        // =========================================================================
        // PASSIVE OS FINGERPRINT PROFILING (p0f)
        // =========================================================================
        ss << ANSI::CYAN << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n"
           << "║ " << ANSI::WHITE << ANSI::BOLD << "[ PASSIVE TCP CLIENT OS PROFILES (p0f) ]" << ANSI::CYAN << std::string(46, ' ') << "║\n" << ANSI::RESET;

        if (!gstats.os_distribution.empty()) {
            size_t os_total = 0;
            for (const auto& p : gstats.os_distribution) os_total += p.second;

            ss << ANSI::CYAN << "║  " << ANSI::RESET;
            for (const auto& [os_name, count] : gstats.os_distribution) {
                double pct = os_total > 0 ? (100.0 * count / os_total) : 0.0;
                ss << ANSI::WHITE << ANSI::BOLD << os_name << ": " << ANSI::GREEN << count << ANSI::RESET
                   << ANSI::DIM << " (" << std::fixed << std::setprecision(1) << pct << "%) " << ANSI::RESET << " | ";
            }
            ss << ANSI::CYAN << "  ║\n";
        } else {
            ss << ANSI::CYAN << "║  " << ANSI::DIM << "Awaiting incoming TCP SYN packets for passive OS profiling..."
               << ANSI::CYAN << std::string(22, ' ') << "║\n";
        }

        // =========================================================================
        // LAYER-7 APPLICATION WATERFALL
        // =========================================================================
        ss << ANSI::CYAN << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n"
           << "║ " << ANSI::WHITE << ANSI::BOLD << "[ LAYER-7 APPLICATION WATERFALL CLASSIFICATION ]" << ANSI::CYAN << std::string(38, ' ') << "║\n" << ANSI::RESET;

        std::vector<std::pair<AppType, size_t>> sorted_apps(
            gstats.app_distribution.begin(), gstats.app_distribution.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        size_t app_total = 0;
        for (const auto& p : sorted_apps) app_total += p.second;

        size_t shown = 0;
        for (const auto& [app, count] : sorted_apps) {
            if (shown++ >= 6) break; // Top 6 apps
            double ratio = app_total > 0 ? (static_cast<double>(count) / app_total) : 0.0;
            std::string bar = renderProgressBar(ratio, 14, ANSI::GREEN);
            std::string app_str = appTypeToString(app);
            if (app_str.length() > 14) app_str = app_str.substr(0, 14);

            ss << ANSI::CYAN << "║  " << ANSI::WHITE << std::setw(14) << std::left << app_str
               << " [" << bar << "] "
               << ANSI::WHITE << std::setw(4) << count << " flows"
               << ANSI::CYAN << " (" << std::setw(4) << std::fixed << std::setprecision(1) << (ratio * 100.0) << "%)"
               << ANSI::CYAN << std::string(33, ' ') << "║\n";
        }
    }

    // =========================================================================
    // MULTI-QUEUE CAPTURE SINK STORAGE
    // =========================================================================
    if (capture_interface) {
        ss << ANSI::CYAN << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n"
           << "║ " << ANSI::WHITE << ANSI::BOLD << "[ MULTI-QUEUE PCAP SINK STATUS ]" << ANSI::CYAN << std::string(54, ' ') << "║\n" << ANSI::RESET;

        auto shards = capture_interface->getAllShardStats();
        for (size_t s = 0; s < shards.size(); ++s) {
            const auto& sh = shards[s];
            std::string f_display = (sh.filename.length() > 24) ? (sh.filename.substr(0, 21) + "...") : sh.filename;
            ss << ANSI::CYAN << "║  " << ANSI::WHITE << "Queue #" << s << " (" << std::setw(24) << std::left << f_display << "): "
               << ANSI::GREEN << std::setw(6) << sh.packets_written << " pkts" << ANSI::RESET
               << " | In-Flight: " << ANSI::CYAN << std::setw(4) << sh.current_queue_depth << ANSI::RESET
               << " | Rate: " << ANSI::WHITE << std::setw(6) << std::fixed << std::setprecision(1) << sh.write_rate_pps << " pps" << ANSI::RESET
               << ANSI::CYAN << "    ║\n";
        }
    }

    // =========================================================================
    // ACTIVE NIDS & FILTERING RULES
    // =========================================================================
    if (rule_mgr) {
        auto rstats = rule_mgr->getStats();
        ss << ANSI::CYAN << "╠══════════════════════════════════════════════════════════════════════════════════════╣\n"
           << "║ " << ANSI::WHITE << ANSI::BOLD << "[ ACTIVE NIDS DEFENSE & FILTERING POLICIES ]" << ANSI::CYAN << std::string(42, ' ') << "║\n" << ANSI::RESET
           << ANSI::CYAN << "║  " << ANSI::WHITE << "Blocked IPs/CIDRs: " << ANSI::YELLOW << rstats.blocked_ips << ANSI::RESET
           << " | Blocked Apps: " << ANSI::YELLOW << rstats.blocked_apps << ANSI::RESET
           << " | Blocked Domains: " << ANSI::YELLOW << rstats.blocked_domains << ANSI::RESET
           << " | L7 Signatures: " << ANSI::YELLOW << rstats.blocked_signatures << ANSI::RESET
           << ANSI::CYAN << std::string(15, ' ') << "║\n";
    }

    ss << ANSI::CYAN << "╚══════════════════════════════════════════════════════════════════════════════════════╝" << ANSI::RESET << "\n";

    return ss.str();
}

void TUIDashboard::renderToTerminal(
    const DPIStats& stats,
    const LBManager* lb_mgr,
    const FPManager* fp_mgr,
    const GlobalConnectionTable* conn_table,
    const TrafficOrchestrator* orchestrator,
    const MultiQueueCaptureInterface* capture_interface,
    const RuleManager* rule_mgr
) {
    std::cout << render(stats, lb_mgr, fp_mgr, conn_table, orchestrator, capture_interface, rule_mgr, false);
}

} // namespace DPI
