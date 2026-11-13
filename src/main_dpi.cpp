#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include "dpi_engine.h"

using namespace DPI;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v2.0                            ║
║       Multi-threaded Deep Packet Inspection & Filtering      ║
║       Orchestrated Multi-Source & Traffic Shaping Engine     ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap ...> <output.pcap> [options]
   or: )" << program << R"( --inputs <host1.pcap> <host2.pcap> -o <output.pcap> [options]

Arguments:
  input.pcap            One or more input PCAP files (captured network traffic)
  output.pcap           Output PCAP file (forwarded traffic)

Multi-Host Orchestration Options (Source Ingestion):
  --inputs <f1> <f2>... Specify multiple host PCAP capture files
  --input <file>        Add an input capture file (repeatable)
  -o, --output <file>   Specify output PCAP file / shard prefix
  --ingest-mode <mode>  Ingestion strategy: chrono (default) or fair-round-robin

Multi-Queue Capture Interface Options (Sink Demuxing):
  --out-shards <n>      Number of concurrent output PCAP queues/files (default: 1)
  --out-routing <mode>  Sink routing: least-loaded (default), flow-affinity, round-robin
  --out-rate-limit <pps> Shard write pacing rate limit
  --out-burst-size <tokens> Shard burst tolerance tokens

Traffic Shaping & QoS Options:
  --shaper <algo>       Shaping algorithm: token-bucket (default), leaky-bucket, none
  --rate-limit <pps>    Sustained packet rate limit (packets per second)
  --burst-size <tokens> Burst tolerance capacity (default: 1000 tokens)
  --bandwidth <mbps>    Bandwidth rate limit in Mbps (0 = unlimited)
  --no-qos              Disable QoS priority bypass for handshakes (SYN/FIN/RST) & DNS

Filtering Options:
  --block-ip <ip/cidr>  Block packets from IP or CIDR subnet (e.g., 10.0.0.0/8)
  --block-app <app>     Block application (e.g., YouTube, Netflix, ChatGPT)
  --block-domain <dom>  Block domain or wildcard (e.g., *.tiktok.com)
  --block-port <port>   Block destination port (e.g., 8080)
  --block-payload <sig> Block L7 payload signature via Aho-Corasick (e.g. "UNION SELECT")
  --enable-nids         Enable default NIDS attack signatures (SQLi, RCE, Webshells)
  --enable-security-intel Enable Shannon Entropy DGA C2 & DNS tunneling detection
  --dga-threshold <val> Set DGA Shannon Entropy threshold (default: 3.6)
  --flow-limit-kbps <n> Default per-flow micro bandwidth quota in KB/s (0 = unlimited)
  --app-flow-limit <app>:<n> Per-app flow rate limit in KB/s (e.g. YouTube:500)
  --rules <file>        Load blocking rules from text file

Execution & Telemetry:
  --lbs <n>             Number of load balancer threads (default: 2)
  --fps <n>             FP threads per LB (default: 2)
  --tui, --dashboard    Display mission-critical ANSI Cyber-Ops HUD Dashboard
  --export-json <file>  Export full metrics and telemetry to JSON file
  --benchmark           Measure and display throughput (pps & Gbps)
  --verbose             Enable verbose logging
  --help, -h            Show this help message

Supported Application Signatures:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord,
  GitHub, Cloudflare, ChatGPT, Claude, Reddit, LinkedIn, Twitch, Slack
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::vector<std::string> input_files;
    std::string output_file;

    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;
    config.orchestrator_config.shaper_config.algorithm = ShaperAlgorithm::TOKEN_BUCKET;
    config.orchestrator_config.shaper_config.burst_capacity = 1000.0;
    config.orchestrator_config.shaper_config.enable_qos_priority = true;

    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    std::vector<std::string> block_payloads;
    bool enable_nids = false;
    bool enable_security_intel = false;
    double dga_threshold = 3.6;
    double default_flow_limit_bps = 0.0;
    std::vector<std::pair<std::string, double>> app_flow_limits;
    std::string rules_file;
    std::string export_json_file;
    bool benchmark = false;
    bool show_tui = false;

    std::vector<std::string> positional_args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--inputs") {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                input_files.push_back(argv[++i]);
            }
        } else if (arg == "--input" && i + 1 < argc) {
            input_files.push_back(argv[++i]);
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--ingest-mode" && i + 1 < argc) {
            config.orchestrator_config.ingestion_mode = stringToIngestionMode(argv[++i]);
        } else if (arg == "--out-shards" && i + 1 < argc) {
            config.capture_sink_config.num_shards = std::stoul(argv[++i]);
        } else if (arg == "--out-routing" && i + 1 < argc) {
            config.capture_sink_config.routing_policy = stringToRoutingPolicy(argv[++i]);
        } else if (arg == "--out-rate-limit" && i + 1 < argc) {
            config.capture_sink_config.shaper_config.algorithm = ShaperAlgorithm::TOKEN_BUCKET;
            config.capture_sink_config.shaper_config.rate_limit_pps = std::stod(argv[++i]);
        } else if (arg == "--out-burst-size" && i + 1 < argc) {
            config.capture_sink_config.shaper_config.burst_capacity = std::stod(argv[++i]);
        } else if (arg == "--shaper" && i + 1 < argc) {
            config.orchestrator_config.shaper_config.algorithm = stringToShaperAlgorithm(argv[++i]);
        } else if (arg == "--rate-limit" && i + 1 < argc) {
            config.orchestrator_config.shaper_config.rate_limit_pps = std::stod(argv[++i]);
        } else if (arg == "--burst-size" && i + 1 < argc) {
            config.orchestrator_config.shaper_config.burst_capacity = std::stod(argv[++i]);
        } else if (arg == "--bandwidth" && i + 1 < argc) {
            config.orchestrator_config.shaper_config.bandwidth_limit_mbps = std::stod(argv[++i]);
        } else if (arg == "--no-qos") {
            config.orchestrator_config.shaper_config.enable_qos_priority = false;
        } else if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--block-port" && i + 1 < argc) {
            block_ports.push_back(static_cast<uint16_t>(std::stoi(argv[++i])));
        } else if (arg == "--block-payload" && i + 1 < argc) {
            block_payloads.push_back(argv[++i]);
        } else if (arg == "--enable-nids") {
            enable_nids = true;
        } else if (arg == "--enable-security-intel") {
            enable_security_intel = true;
        } else if (arg == "--dga-threshold" && i + 1 < argc) {
            dga_threshold = std::stod(argv[++i]);
        } else if (arg == "--flow-limit-kbps" && i + 1 < argc) {
            default_flow_limit_bps = std::stod(argv[++i]) * 1024.0;
        } else if (arg == "--app-flow-limit" && i + 1 < argc) {
            std::string spec = argv[++i];
            size_t colon = spec.find(':');
            if (colon != std::string::npos) {
                std::string app = spec.substr(0, colon);
                double kbps = std::stod(spec.substr(colon + 1));
                app_flow_limits.push_back({app, kbps * 1024.0});
            }
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--export-json" && i + 1 < argc) {
            export_json_file = argv[++i];
        } else if (arg == "--benchmark") {
            benchmark = true;
        } else if (arg == "--tui" || arg == "--dashboard") {
            show_tui = true;
        } else if (arg == "--lbs" && i + 1 < argc) {
            config.num_load_balancers = std::stoi(argv[++i]);
        } else if (arg == "--fps" && i + 1 < argc) {
            config.fps_per_lb = std::stoi(argv[++i]);
        } else if (arg == "--verbose") {
            config.verbose = true;
            config.orchestrator_config.verbose = true;
        } else if (arg.rfind("-", 0) == 0) {
            std::cerr << "Unknown option: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        } else {
            positional_args.push_back(arg);
        }
    }

    // Process positional arguments if --inputs was not explicitly given
    if (input_files.empty() && !positional_args.empty()) {
        if (output_file.empty()) {
            if (positional_args.size() >= 2) {
                output_file = positional_args.back();
                for (size_t i = 0; i < positional_args.size() - 1; ++i) {
                    input_files.push_back(positional_args[i]);
                }
            } else {
                std::cerr << "Error: Output PCAP destination required\n";
                printUsage(argv[0]);
                return 1;
            }
        } else {
            for (const auto& arg : positional_args) {
                input_files.push_back(arg);
            }
        }
    } else if (output_file.empty() && !positional_args.empty()) {
        output_file = positional_args.back();
    }

    if (input_files.empty() || output_file.empty()) {
        std::cerr << "Error: At least one input file and one output file are required\n";
        printUsage(argv[0]);
        return 1;
    }

    // Create DPI engine
    DPIEngine engine(config);

    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }

    // Load rules from file if specified
    if (!rules_file.empty()) {
        engine.loadRules(rules_file);
    }

    // Apply command-line blocking rules
    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }

    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }

    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }

    for (uint16_t port : block_ports) {
        engine.blockPort(port);
    }

    if (enable_nids) {
        engine.loadDefaultNIDSSignatures();
    }

    if (enable_security_intel) {
        engine.enableSecurityAnomalyDetection(true);
        engine.setDGAEntropyThreshold(dga_threshold);
    }

    if (default_flow_limit_bps > 0.0) {
        engine.setDefaultFlowRateLimit(default_flow_limit_bps);
    }

    for (const auto& [app_name, bps] : app_flow_limits) {
        engine.setAppFlowRateLimit(app_name, bps);
    }

    for (const auto& sig : block_payloads) {
        engine.blockPayloadSignature(sig);
    }

    // Process the files
    auto start_time = std::chrono::high_resolution_clock::now();

    if (!engine.processFiles(input_files, output_file)) {
        std::cerr << "Failed to process files\n";
        return 1;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();

    if (benchmark) {
        const auto& stats = engine.getStats();
        double pps = stats.total_packets.load() / (elapsed_sec > 0 ? elapsed_sec : 0.000001);
        double mbps = (stats.total_bytes.load() * 8.0) / (elapsed_sec * 1000000.0);

        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                     BENCHMARK RESULTS                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Processing Time:    " << std::setw(10) << std::fixed << std::setprecision(4) << elapsed_sec << " seconds                       ║\n";
        std::cout << "║ Packet Rate:        " << std::setw(10) << std::fixed << std::setprecision(0) << pps << " packets/sec                   ║\n";
        std::cout << "║ Data Throughput:    " << std::setw(10) << std::fixed << std::setprecision(2) << mbps << " Mbps                          ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    }

    // Export JSON if requested
    if (!export_json_file.empty()) {
        engine.exportJsonReport(export_json_file);
    }

    // Display ANSI Cyber-Ops HUD Dashboard if requested
    if (show_tui) {
        engine.printDashboard();
    }

    std::cout << "\n\033[1;32mProcessing complete!\033[0m\n";
    std::cout << "Output written to: \033[33m" << output_file << "\033[0m\n";

    return 0;
}
