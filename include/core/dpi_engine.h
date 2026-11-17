#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "core/types.h"
#include "protocol/pcap_reader.h"
#include "protocol/packet_parser.h"
#include "core/load_balancer.h"
#include "core/fast_path.h"
#include "security/rule_manager.h"
#include "core/connection_tracker.h"
#include "traffic/traffic_orchestrator.h"
#include "traffic/multiqueue_pcap_writer.h"
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>

namespace DPI {

// ============================================================================
// DPI Engine - Main orchestrator
// ============================================================================
//
// Architecture Overview:
//
//   +------------------+
//   |   PCAP Reader    |  (Reads packets from input file)
//   +--------+---------+
//            |
//            v (hash to select LB)
//   +--------+----------+
//   |   Load Balancers  |  (2 LB threads)
//   |   LB0      LB1    |
//   +----+--------+-----+
//        |        |
//        v        v (hash to select FP within LB's pool)
//   +----+--------+-----+
//   |  Fast Path Procs  |  (4 FP threads, 2 per LB)
//   |  FP0 FP1  FP2 FP3 |
//   +----+--------+-----+
//        |        |
//        v        v
//   +----+--------+-----+
//   |   Output Queue    |  (Packets to forward)
//   +----+--------+-----+
//        |
//        v
//   +----+--------+-----+
//   |   Output Writer   |  (Writes to output PCAP)
//   +-------------------+
//
// ============================================================================

class DPIEngine {
public:
    // Configuration
    struct Config {
        int num_load_balancers = 2;
        int fps_per_lb = 2;
        size_t queue_size = 10000;
        std::string rules_file;
        bool verbose = false;
        OrchestratorConfig orchestrator_config;
        MultiQueueCaptureConfig capture_sink_config;
    };
    
    DPIEngine(const Config& config);
    ~DPIEngine();
    
    // Initialize the engine (create threads, queues)
    bool initialize();
    
    // Process a single PCAP file
    bool processFile(const std::string& input_file, 
                     const std::string& output_file);

    // Process multiple PCAP files via Orchestrator (Multi-Host / Distributed captures)
    bool processFiles(const std::vector<std::string>& input_files,
                      const std::string& output_file);
    
    // Start the engine (starts all threads)
    void start();
    
    // Stop the engine (stops all threads)
    void stop();
    
    // Wait for processing to complete
    void waitForCompletion();
    
    // ========== Rule Management ==========
    
    // Block an IP address
    void blockIP(const std::string& ip);
    
    // Unblock an IP address
    void unblockIP(const std::string& ip);
    
    // Block an application
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    
    // Unblock an application
    void unblockApp(AppType app);
    void unblockApp(const std::string& app_name);
    
    // Block a domain
    void blockDomain(const std::string& domain);
    
    // Unblock a domain
    void unblockDomain(const std::string& domain);
    
    // Block a CIDR subnet
    void blockCIDR(const std::string& cidr);
    
    // Block a port
    void blockPort(uint16_t port);
    void unblockPort(uint16_t port);
    
    // Block an L7 payload signature via Aho-Corasick (e.g. "UNION SELECT", "/bin/sh")
    void blockPayloadSignature(const std::string& signature, const std::string& rule_name = "");
    
    // Load pre-configured NIDS signatures (SQLi, RCE, Webshells, Traversal)
    void loadDefaultNIDSSignatures();

    // Enable Security Anomaly Detection (Shannon entropy DGA & DNS Tunneling)
    void enableSecurityAnomalyDetection(bool enable = true);
    void setDGAEntropyThreshold(double threshold);

    // Set per-flow default or per-application bandwidth limits (in bytes/sec and burst bytes)
    void setDefaultFlowRateLimit(double bytes_per_sec, double burst_bytes = 65536.0);
    void setAppFlowRateLimit(AppType app, double bytes_per_sec, double burst_bytes = 65536.0);
    void setAppFlowRateLimit(const std::string& app_name, double bytes_per_sec, double burst_bytes = 65536.0);
    
    // Load rules from file
    bool loadRules(const std::string& filename);
    
    // Save rules to file
    bool saveRules(const std::string& filename);
    
    // ========== Reporting ==========
    
    // Generate full statistics report
    std::string generateReport() const;
    
    // Generate classification report (app distribution)
    std::string generateClassificationReport() const;
    
    // Export full statistics and classification to structured JSON
    bool exportJsonReport(const std::string& filename) const;

    // Render & display live Cyber-Ops ANSI TUI Dashboard
    std::string generateDashboard() const;
    void printDashboard() const;
    
    // Get real-time statistics
    const DPIStats& getStats() const;
    
    // Print live status
    void printStatus() const;
    
    // ========== Accessors ==========
    
    RuleManager& getRuleManager() { return *rule_manager_; }
    const Config& getConfig() const { return config_; }
    bool isRunning() const { return running_; }
    TrafficOrchestrator* getOrchestrator() { return orchestrator_.get(); }
    const TrafficOrchestrator* getOrchestrator() const { return orchestrator_.get(); }
    MultiQueueCaptureInterface* getCaptureInterface() { return capture_interface_.get(); }
    const MultiQueueCaptureInterface* getCaptureInterface() const { return capture_interface_.get(); }

private:
    Config config_;
    
    // Shared components
    std::unique_ptr<RuleManager> rule_manager_;
    std::unique_ptr<GlobalConnectionTable> global_conn_table_;
    std::unique_ptr<TrafficOrchestrator> orchestrator_;
    std::unique_ptr<MultiQueueCaptureInterface> capture_interface_;
    
    // Thread pools
    std::unique_ptr<FPManager> fp_manager_;
    std::unique_ptr<LBManager> lb_manager_;
    
    // Output handling
    ThreadSafeQueue<PacketJob> output_queue_;
    std::thread output_thread_;
    std::ofstream output_file_;
    std::mutex output_mutex_;
    
    // Statistics
    DPIStats stats_;
    
    // Control
    std::atomic<bool> running_{false};
    std::atomic<bool> processing_complete_{false};
    
    // Reader thread (separate for PCAP input)
    std::thread reader_thread_;
    
    // Output handling
    void outputThreadFunc();
    void handleOutput(const PacketJob& job, PacketAction action);
    
    // Write PCAP header to output file
    bool writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header);
    
    // Write a packet to output file
    void writeOutputPacket(const PacketJob& job);
    
    // Reader function
    void readerThreadFunc(const std::string& input_file);
    
    // Convert ParsedPacket to PacketJob
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                               const PacketAnalyzer::ParsedPacket& parsed,
                               uint32_t packet_id);
};

} // namespace DPI

#endif // DPI_ENGINE_H
