#include "core/dpi_engine.h"
#include "ui/tui_dashboard.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }

    // Stop and flush multi-queue capture sinks
    if (capture_interface_) {
        capture_interface_->close();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Wait a bit for queues to drain
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    return processFiles({input_file}, output_file);
}

bool DPIEngine::processFiles(const std::vector<std::string>& input_files,
                             const std::string& output_file) {
    if (input_files.empty()) {
        std::cerr << "[DPIEngine] Error: No input PCAP files specified\n";
        return false;
    }

    std::cout << "\n================================================================================\n";
    std::cout << "[DPIEngine] Ingesting " << input_files.size() << " capture stream(s):\n";
    for (size_t i = 0; i < input_files.size(); ++i) {
        std::cout << "  Host Source #" << i << ": " << input_files[i] << "\n";
    }
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n";
    std::cout << "================================================================================\n\n";
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Initialize MultiQueue Capture Interface
    capture_interface_ = std::make_unique<MultiQueueCaptureInterface>(config_.capture_sink_config);

    // Set up Traffic Orchestrator
    orchestrator_ = std::make_unique<TrafficOrchestrator>(config_.orchestrator_config);
    if (!orchestrator_->addSources(input_files)) {
        std::cerr << "[DPIEngine] Error: Failed to initialize PCAP input sources\n";
        return false;
    }
    orchestrator_->setLoadBalancerManager(lb_manager_.get());
    
    // Start processing threads
    start();
    
    // Start orchestrator thread
    reader_thread_ = std::thread([this, output_file]() {
        orchestrator_->run(
            running_,
            [this, &output_file](const PacketAnalyzer::PcapGlobalHeader& header) {
                if (capture_interface_) {
                    capture_interface_->initialize(output_file, header);
                }
                writeOutputHeader(header);
            },
            [this](const PacketJob& job) {
                stats_.total_packets++;
                stats_.total_bytes += job.data.size();
                if (job.tuple.protocol == 6) {
                    stats_.tcp_packets++;
                } else if (job.tuple.protocol == 17) {
                    stats_.udp_packets++;
                } else {
                    stats_.other_packets++;
                }
            }
        );
    });
    
    // Wait for completion
    waitForCompletion();
    
    // Give some time for final packets to process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Stop all threads
    stop();
    
    // Close output file if open
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    // Print final reports
    std::cout << generateReport();
    if (orchestrator_) {
        std::cout << orchestrator_->generateReport();
    }
    if (capture_interface_) {
        std::cout << capture_interface_->generateLiveLoadReport();
    }
    std::cout << fp_manager_->generateClassificationReport();
    
    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    processFile(input_file, "output.pcap");
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Direct zero-copy assignment of five-tuple (supports IPv4 & IPv6)
    job.tuple.ip_version = parsed.ip_version;
    if (parsed.ip_version == 4) {
        job.tuple.src_ip = parsed.src_ip_v4;
        job.tuple.dst_ip = parsed.dest_ip_v4;
    } else {
        job.tuple.src_ip6 = parsed.src_ip_v6;
        job.tuple.dst_ip6 = parsed.dest_ip_v6;
    }
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags & IP metrics
    job.tcp_flags = parsed.tcp_flags;
    job.ttl = parsed.ttl;
    job.window_size = parsed.window_size;
    
    // Copy packet data
    job.data = raw.data;
    
    // Offsets calculated directly from parser
    job.eth_offset = 0;
    job.ip_offset = 14;
    job.payload_offset = parsed.payload_offset;
    job.payload_length = parsed.payload_length;
    if (job.payload_length > 0 && job.payload_offset < job.data.size()) {
        job.payload_data = job.data.data() + job.payload_offset;
    } else {
        job.payload_data = nullptr;
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (running_ || !output_queue_.empty()) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    if (capture_interface_) {
        capture_interface_->dispatch(job);
    } else {
        output_queue_.push(job);
    }
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

void DPIEngine::blockCIDR(const std::string& cidr) {
    if (rule_manager_) {
        rule_manager_->blockCIDR(cidr);
    }
}

void DPIEngine::blockPort(uint16_t port) {
    if (rule_manager_) {
        rule_manager_->blockPort(port);
    }
}

void DPIEngine::unblockPort(uint16_t port) {
    if (rule_manager_) {
        rule_manager_->unblockPort(port);
    }
}

void DPIEngine::blockPayloadSignature(const std::string& signature, const std::string& rule_name) {
    if (rule_manager_) {
        rule_manager_->blockPayloadSignature(signature, rule_name);
    }
}

void DPIEngine::loadDefaultNIDSSignatures() {
    if (rule_manager_) {
        rule_manager_->loadDefaultNIDSSignatures();
    }
}

void DPIEngine::enableSecurityAnomalyDetection(bool enable) {
    if (rule_manager_) {
        rule_manager_->enableSecurityAnomalyDetection(enable);
    }
}

void DPIEngine::setDGAEntropyThreshold(double threshold) {
    if (rule_manager_) {
        rule_manager_->setDGAEntropyThreshold(threshold);
    }
}

void DPIEngine::setDefaultFlowRateLimit(double bytes_per_sec, double burst_bytes) {
    if (rule_manager_) {
        rule_manager_->setDefaultFlowRateLimit(bytes_per_sec, burst_bytes);
    }
}

void DPIEngine::setAppFlowRateLimit(AppType app, double bytes_per_sec, double burst_bytes) {
    if (rule_manager_) {
        rule_manager_->setAppFlowRateLimit(app, bytes_per_sec, burst_bytes);
    }
}

void DPIEngine::setAppFlowRateLimit(const std::string& app_name, double bytes_per_sec, double burst_bytes) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        AppType app = static_cast<AppType>(i);
        if (appTypeToString(app) == app_name) {
            setAppFlowRateLimit(app, bytes_per_sec, burst_bytes);
            return;
        }
    }
    std::cerr << "[DPIEngine] Warning: Unknown application name for rate limit: " << app_name << "\n";
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
        for (int i = 0; i < lb_manager_->getNumLBs(); i++) {
            auto s = lb_manager_->getLB(i).getStats();
            ss << "║     LB" << i << " dispatched:   " << std::setw(10) << s.packets_dispatched << "                        ║\n";
        }
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   FP Rate Limited:    " << std::setw(12) << fp_stats.total_rate_limited << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            auto s = fp_manager_->getFP(i).getStats();
            ss << "║     FP" << i << " processed:    " << std::setw(10) << s.packets_processed
               << " (dropped: " << std::setw(4) << s.packets_dropped
               << ", rate-lmt: " << std::setw(3) << s.rate_limited_dropped << ") ║\n";
        }
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs/CIDRs:  " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
        ss << "║   L7 Signatures:      " << std::setw(12) << rule_stats.blocked_signatures << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

bool DPIEngine::exportJsonReport(const std::string& filename) const {
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open " << filename << " for JSON export\n";
        return false;
    }

    out << "{\n";
    out << "  \"engine\": \"DPI Engine v2.0\",\n";
    out << "  \"packet_statistics\": {\n";
    out << "    \"total_packets\": " << stats_.total_packets.load() << ",\n";
    out << "    \"total_bytes\": " << stats_.total_bytes.load() << ",\n";
    out << "    \"tcp_packets\": " << stats_.tcp_packets.load() << ",\n";
    out << "    \"udp_packets\": " << stats_.udp_packets.load() << ",\n";
    out << "    \"forwarded_packets\": " << stats_.forwarded_packets.load() << ",\n";
    out << "    \"dropped_packets\": " << stats_.dropped_packets.load() << "\n";
    out << "  },\n";

    if (lb_manager_) {
        out << "  \"load_balancers\": [\n";
        for (int i = 0; i < lb_manager_->getNumLBs(); i++) {
            auto s = lb_manager_->getLB(i).getStats();
            out << "    {\"id\": " << i << ", \"dispatched\": " << s.packets_dispatched << "}"
                << (i + 1 < lb_manager_->getNumLBs() ? ",\n" : "\n");
        }
        out << "  ],\n";
    }

    if (fp_manager_) {
        out << "  \"fast_paths\": [\n";
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            auto s = fp_manager_->getFP(i).getStats();
            out << "    {\"id\": " << i << ", \"processed\": " << s.packets_processed
                << ", \"forwarded\": " << s.packets_forwarded
                << ", \"dropped\": " << s.packets_dropped
                << ", \"rate_limited\": " << s.rate_limited_dropped << "}"
                << (i + 1 < fp_manager_->getNumFPs() ? ",\n" : "\n");
        }
        out << "  ],\n";
    }

    if (global_conn_table_) {
        auto gstats = global_conn_table_->getGlobalStats();
        out << "  \"connection_statistics\": {\n";
        out << "    \"total_connections_seen\": " << gstats.total_connections_seen << ",\n";
        out << "    \"active_connections\": " << gstats.total_active_connections << ",\n";
        out << "    \"app_distribution\": {\n";
        size_t app_idx = 0;
        for (const auto& [app, cnt] : gstats.app_distribution) {
            out << "      \"" << appTypeToString(app) << "\": " << cnt
                << (++app_idx < gstats.app_distribution.size() ? ",\n" : "\n");
        }
        out << "    },\n";
        out << "    \"top_domains\": [\n";
        for (size_t d = 0; d < gstats.top_domains.size(); d++) {
            out << "      {\"domain\": \"" << gstats.top_domains[d].first << "\", \"count\": " << gstats.top_domains[d].second << "}"
                << (d + 1 < gstats.top_domains.size() ? ",\n" : "\n");
        }
        out << "    ],\n";
        out << "    \"os_distribution\": {\n";
        size_t os_idx = 0;
        for (const auto& [os_name, cnt] : gstats.os_distribution) {
            out << "      \"" << os_name << "\": " << cnt
                << (++os_idx < gstats.os_distribution.size() ? ",\n" : "\n");
        }
        out << "    },\n";
        out << "    \"security_threats\": {\n";
        out << "      \"dga_detected_count\": " << gstats.total_dga_detected << ",\n";
        out << "      \"dga_alerts\": [\n";
        for (size_t a = 0; a < gstats.dga_alerts.size(); a++) {
            out << "        {\"domain\": \"" << gstats.dga_alerts[a].first << "\", \"entropy\": " << gstats.dga_alerts[a].second << "}"
                << (a + 1 < gstats.dga_alerts.size() ? ",\n" : "\n");
        }
        out << "      ],\n";
        out << "      \"dns_tunneling_count\": " << gstats.total_dns_tunneling_detected << ",\n";
        out << "      \"dns_tunneling_alerts\": [\n";
        for (size_t t = 0; t < gstats.dns_tunneling_alerts.size(); t++) {
            out << "        \"" << gstats.dns_tunneling_alerts[t] << "\""
                << (t + 1 < gstats.dns_tunneling_alerts.size() ? ",\n" : "\n");
        }
        out << "      ]\n";
        out << "    }\n";
        out << "  }";
    }

    if (orchestrator_) {
        auto ostats = orchestrator_->getStats();
        out << ",\n  \"orchestrator\": {\n";
        out << "    \"ingestion_mode\": \"" << ingestionModeToString(orchestrator_->getConfig().ingestion_mode) << "\",\n";
        out << "    \"total_packets_read\": " << ostats.total_packets << ",\n";
        out << "    \"total_bytes_read\": " << ostats.total_bytes << ",\n";
        out << "    \"elapsed_seconds\": " << ostats.elapsed_seconds << ",\n";
        out << "    \"throughput_pps\": " << ostats.throughput_pps << ",\n";
        out << "    \"throughput_mbps\": " << ostats.throughput_mbps << ",\n";
        out << "    \"traffic_shaper\": {\n";
        out << "      \"algorithm\": \"" << shaperAlgorithmToString(orchestrator_->getConfig().shaper_config.algorithm) << "\",\n";
        out << "      \"admitted_packets\": " << ostats.shaper_stats.total_admitted << ",\n";
        out << "      \"burst_packets\": " << ostats.shaper_stats.burst_packets << ",\n";
        out << "      \"delayed_packets\": " << ostats.shaper_stats.delayed_packets << ",\n";
        out << "      \"high_priority_expedited\": " << ostats.shaper_stats.high_priority_expedited << ",\n";
        out << "      \"total_delay_seconds\": " << ostats.shaper_stats.total_delay_seconds << "\n";
        out << "    },\n";
        out << "    \"sources\": [\n";
        for (size_t s = 0; s < ostats.per_source_stats.size(); s++) {
            const auto& src = ostats.per_source_stats[s];
            out << "      {\"id\": " << src.source_id << ", \"file\": \"" << src.filename
                << "\", \"packets\": " << src.packets_read << ", \"bytes\": " << src.bytes_read << "}"
                << (s + 1 < ostats.per_source_stats.size() ? ",\n" : "\n");
        }
        out << "    ]\n";
        out << "  }";
    }

    if (capture_interface_) {
        auto sstats = capture_interface_->getAllShardStats();
        out << ",\n  \"multiqueue_capture\": {\n";
        out << "    \"routing_policy\": \"" << routingPolicyToString(capture_interface_->getConfig().routing_policy) << "\",\n";
        out << "    \"num_shards\": " << sstats.size() << ",\n";
        out << "    \"shards\": [\n";
        for (size_t i = 0; i < sstats.size(); ++i) {
            const auto& s = sstats[i];
            out << "      {\"id\": " << s.shard_id << ", \"file\": \"" << s.filename
                << "\", \"packets_written\": " << s.packets_written
                << ", \"bytes_written\": " << s.bytes_written
                << ", \"queue_depth\": " << s.current_queue_depth
                << ", \"write_rate_pps\": " << s.write_rate_pps << "}"
                << (i + 1 < sstats.size() ? ",\n" : "\n");
        }
        out << "    ]\n";
        out << "  }\n";
    } else {
        out << "\n";
    }

    out << "}\n";
    out.close();
    std::cout << "[DPIEngine] Exported JSON report to: " << filename << "\n";
    return true;
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

std::string DPIEngine::generateDashboard() const {
    return TUIDashboard::render(
        stats_,
        lb_manager_.get(),
        fp_manager_.get(),
        global_conn_table_.get(),
        orchestrator_.get(),
        capture_interface_.get(),
        rule_manager_.get(),
        false
    );
}

void DPIEngine::printDashboard() const {
    std::cout << generateDashboard() << std::flush;
}

} // namespace DPI
