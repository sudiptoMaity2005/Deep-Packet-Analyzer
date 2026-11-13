#ifndef TUI_DASHBOARD_H
#define TUI_DASHBOARD_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "types.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "connection_tracker.h"
#include "traffic_orchestrator.h"
#include "multiqueue_pcap_writer.h"
#include "rule_manager.h"

namespace DPI {

// ============================================================================
// Real-Time Live ANSI Cyber-Ops TUI Dashboard
// Renders mission-critical cyber defense metrics, core dispatch balance,
// Shannon entropy threat radars, and protocol classification waterfalls.
// ============================================================================
class TUIDashboard {
public:
    // Render full ANSI dashboard string
    static std::string render(
        const DPIStats& stats,
        const LBManager* lb_mgr,
        const FPManager* fp_mgr,
        const GlobalConnectionTable* conn_table,
        const TrafficOrchestrator* orchestrator,
        const MultiQueueCaptureInterface* capture_interface,
        const RuleManager* rule_mgr,
        bool live_refresh = false
    );

    // Print rendered dashboard directly to terminal
    static void renderToTerminal(
        const DPIStats& stats,
        const LBManager* lb_mgr,
        const FPManager* fp_mgr,
        const GlobalConnectionTable* conn_table,
        const TrafficOrchestrator* orchestrator,
        const MultiQueueCaptureInterface* capture_interface,
        const RuleManager* rule_mgr
    );

private:
    static std::string renderProgressBar(double fraction, int width = 16, const std::string& fill_color = "\033[1;32m");
};

} // namespace DPI

#endif // TUI_DASHBOARD_H

