#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <chrono>

#include "core/types.h"
#include "protocol/packet_parser.h"
#include "protocol/sni_extractor.h"
#include "security/rule_manager.h"
#include "core/connection_tracker.h"
#include "core/load_balancer.h"
#include "core/fast_path.h"
#include "traffic/traffic_shaper.h"
#include "traffic/traffic_orchestrator.h"
#include "traffic/multiqueue_pcap_writer.h"
#include "security/aho_corasick.h"
#include "security/security_analyzer.h"
#include "ui/tui_dashboard.h"
#include <fstream>
#include <cstdio>

using namespace DPI;
using namespace PacketAnalyzer;

// Simple clean test assertion macro
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[-] Assertion FAILED: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return false; \
        } \
    } while(0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[RUNNING] " << #fn << "... "; \
        if (fn()) { \
            std::cout << "\033[32mPASSED\033[0m\n"; \
            passed++; \
        } else { \
            std::cout << "\033[31mFAILED\033[0m\n"; \
            failed++; \
        } \
    } while(0)

// Test 1: Symmetric Five-Tuple Hashing
bool test_five_tuple_symmetry() {
    FiveTuple fwd;
    fwd.ip_version = 4;
    fwd.src_ip = 0xC0A80164; // 192.168.1.100
    fwd.dst_ip = 0x8EFB96CE; // 142.251.150.206
    fwd.src_port = 54321;
    fwd.dst_port = 443;
    fwd.protocol = 6;

    FiveTuple rev = fwd.reverse();
    TEST_ASSERT(rev.src_ip == fwd.dst_ip, "Reverse src_ip matches fwd dst_ip");
    TEST_ASSERT(rev.dst_ip == fwd.src_ip, "Reverse dst_ip matches fwd src_ip");
    TEST_ASSERT(rev.src_port == fwd.dst_port, "Reverse src_port matches fwd dst_port");
    TEST_ASSERT(rev.dst_port == fwd.src_port, "Reverse dst_port matches fwd src_port");

    FiveTupleHash hasher;
    size_t hash_fwd = hasher(fwd);
    size_t hash_rev = hasher(rev);
    TEST_ASSERT(hash_fwd == hash_rev, "Symmetric hash must be identical for forward and reverse packets");

    // IPv6 symmetry test
    FiveTuple v6_fwd;
    v6_fwd.ip_version = 6;
    v6_fwd.src_ip6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    v6_fwd.dst_ip6 = {0x26, 0x07, 0xf8, 0xb0, 0x40, 0x06, 0x08, 0x1b, 0, 0, 0, 0, 0, 0, 0x20, 0x0e};
    v6_fwd.src_port = 49152;
    v6_fwd.dst_port = 443;
    v6_fwd.protocol = 6;

    FiveTuple v6_rev = v6_fwd.reverse();
    TEST_ASSERT(hasher(v6_fwd) == hasher(v6_rev), "IPv6 forward and reverse hashes must be symmetric");
    return true;
}

// Test 2: Domain Matching Precision (Preventing False Positives)
bool test_domain_matching_precision() {
    // Crucial bug prevention test: Netflix must not match x.com
    TEST_ASSERT(sniToAppType("www.netflix.com") == AppType::NETFLIX, "www.netflix.com must classify as NETFLIX");
    TEST_ASSERT(sniToAppType("netflix.com") == AppType::NETFLIX, "netflix.com must classify as NETFLIX");
    
    // Microsoft must not match t.co
    TEST_ASSERT(sniToAppType("www.microsoft.com") == AppType::MICROSOFT, "www.microsoft.com must classify as MICROSOFT");
    TEST_ASSERT(sniToAppType("microsoft.com") == AppType::MICROSOFT, "microsoft.com must classify as MICROSOFT");
    
    // Twitter / X legitimate matches
    TEST_ASSERT(sniToAppType("twitter.com") == AppType::TWITTER, "twitter.com must classify as TWITTER");
    TEST_ASSERT(sniToAppType("api.twitter.com") == AppType::TWITTER, "api.twitter.com must classify as TWITTER");
    TEST_ASSERT(sniToAppType("x.com") == AppType::TWITTER, "x.com must classify as TWITTER");
    TEST_ASSERT(sniToAppType("mobile.x.com") == AppType::TWITTER, "mobile.x.com must classify as TWITTER");
    TEST_ASSERT(sniToAppType("t.co") == AppType::TWITTER, "t.co must classify as TWITTER");

    // Modern AI services
    TEST_ASSERT(sniToAppType("chatgpt.com") == AppType::CHATGPT, "chatgpt.com must classify as CHATGPT");
    TEST_ASSERT(sniToAppType("api.openai.com") == AppType::CHATGPT, "api.openai.com must classify as CHATGPT");
    TEST_ASSERT(sniToAppType("claude.ai") == AppType::CLAUDE, "claude.ai must classify as CLAUDE");
    TEST_ASSERT(sniToAppType("anthropic.com") == AppType::CLAUDE, "anthropic.com must classify as CLAUDE");

    // Other platforms
    TEST_ASSERT(sniToAppType("www.youtube.com") == AppType::YOUTUBE, "www.youtube.com must classify as YOUTUBE");
    TEST_ASSERT(sniToAppType("www.facebook.com") == AppType::FACEBOOK, "www.facebook.com must classify as FACEBOOK");
    TEST_ASSERT(sniToAppType("reddit.com") == AppType::REDDIT, "reddit.com must classify as REDDIT");
    TEST_ASSERT(sniToAppType("discord.com") == AppType::DISCORD, "discord.com must classify as DISCORD");
    return true;
}

// Test 3: Load Balancer Two-Tier Distribution (No Starvation)
bool test_load_balancer_distribution() {
    constexpr int NUM_LBS = 2;
    constexpr int FPS_PER_LB = 2;
    constexpr int TOTAL_FPS = NUM_LBS * FPS_PER_LB; // 4

    std::vector<ThreadSafeQueue<PacketJob>> queues(TOTAL_FPS);
    std::vector<ThreadSafeQueue<PacketJob>*> queue_ptrs;
    for (int i = 0; i < TOTAL_FPS; i++) {
        queue_ptrs.push_back(&queues[i]);
    }

    LBManager lb_manager(NUM_LBS, FPS_PER_LB, queue_ptrs);
    std::vector<uint32_t> fp_dispatch_count(TOTAL_FPS, 0);

    FiveTupleHash hasher;
    // Simulate 200 distinct connections
    for (uint32_t i = 1; i <= 200; i++) {
        FiveTuple tuple;
        tuple.ip_version = 4;
        tuple.src_ip = 0xC0A80100 + (i % 250);
        tuple.dst_ip = 0x0A000001 + ((i * 37) % 250);
        tuple.src_port = static_cast<uint16_t>(10000 + i);
        tuple.dst_port = 443;
        tuple.protocol = 6;

        size_t lb_idx = hasher(tuple, 0) % NUM_LBS;
        size_t fp_idx_in_lb = hasher(tuple, 0x9e3779b97f4a7c15ULL * (static_cast<uint64_t>(lb_idx) + 1)) % FPS_PER_LB;
        size_t global_fp = lb_idx * FPS_PER_LB + fp_idx_in_lb;

        fp_dispatch_count[global_fp]++;
    }

    for (int i = 0; i < TOTAL_FPS; i++) {
        TEST_ASSERT(fp_dispatch_count[i] > 20, "Each FP thread must receive balanced traffic (no starvation)");
    }
    return true;
}

// Test 4: Rule Manager CIDR Subnet & Wildcard Domain Matching
bool test_rule_manager_cidr_and_wildcards() {
    RuleManager rm;
    
    // Subnet blocking: 10.0.0.0/8
    rm.blockIP("10.0.0.0/8");
    // Parse IP: 10.1.2.3 (network byte order equivalent)
    uint32_t blocked_ip = 10 | (1 << 8) | (2 << 16) | (3 << 24);
    uint32_t allowed_ip = 11 | (1 << 8) | (2 << 16) | (3 << 24);
    TEST_ASSERT(rm.isIPBlocked(blocked_ip), "IP in 10.0.0.0/8 subnet must be blocked");
    TEST_ASSERT(!rm.isIPBlocked(allowed_ip), "IP outside subnet must be allowed");

    // Wildcard domain blocking
    rm.blockDomain("*.tiktok.com");
    TEST_ASSERT(rm.isDomainBlocked("www.tiktok.com"), "Subdomain www.tiktok.com must match *.tiktok.com");
    TEST_ASSERT(rm.isDomainBlocked("tiktok.com"), "Bare domain tiktok.com must match *.tiktok.com");
    TEST_ASSERT(!rm.isDomainBlocked("not-tiktok.com"), "not-tiktok.com must not be blocked");

    // App blocking
    rm.blockApp(AppType::YOUTUBE);
    TEST_ASSERT(rm.isAppBlocked(AppType::YOUTUBE), "YouTube must be blocked");
    TEST_ASSERT(!rm.isAppBlocked(AppType::GOOGLE), "Google must not be blocked when only YouTube is blocked");

    // Port blocking
    rm.blockPort(8080);
    TEST_ASSERT(rm.isPortBlocked(8080), "Port 8080 must be blocked");
    TEST_ASSERT(!rm.isPortBlocked(80), "Port 80 must be allowed");
    return true;
}

// Test 5: Bidirectional Connection Tracking
bool test_connection_tracker_bidirectional() {
    ConnectionTracker tracker(0, 1000);

    FiveTuple client_to_server;
    client_to_server.ip_version = 4;
    client_to_server.src_ip = 0xC0A80164;
    client_to_server.dst_ip = 0x8EFB96CE;
    client_to_server.src_port = 54321;
    client_to_server.dst_port = 443;
    client_to_server.protocol = 6;

    // First packet: client -> server
    Connection* c1 = tracker.getOrCreateConnection(client_to_server);
    TEST_ASSERT(c1 != nullptr, "Connection 1 created");
    tracker.updateConnection(c1, 60, true);

    // Second packet: server -> client (reverse tuple)
    FiveTuple server_to_client = client_to_server.reverse();
    Connection* c2 = tracker.getOrCreateConnection(server_to_client);
    TEST_ASSERT(c1 == c2, "Reverse tuple must map to the EXACT same connection instance");
    tracker.updateConnection(c2, 60, false);

    TEST_ASSERT(c1->packets_out == 1, "One outbound packet recorded");
    TEST_ASSERT(c1->packets_in == 1, "One inbound packet recorded");
    TEST_ASSERT(tracker.getActiveCount() == 1, "Total active connections must be exactly 1");

    // Classify connection
    tracker.classifyConnection(c2, AppType::YOUTUBE, "www.youtube.com");
    TEST_ASSERT(c1->app_type == AppType::YOUTUBE, "Classification must reflect across both directions");
    TEST_ASSERT(c1->sni == "www.youtube.com", "SNI must be shared");

    // Block connection
    tracker.blockConnection(c1);
    TEST_ASSERT(c2->state == ConnectionState::BLOCKED, "Blocking must apply bidirectionally");
    return true;
}

// Test 6: HTTP Host and DNS Query Extraction
bool test_http_and_dns_extraction() {
    // HTTP Request test
    std::string http_req = "GET /index.html HTTP/1.1\r\nHost: example.org:8080\r\nUser-Agent: test\r\n\r\n";
    auto host = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_req.data()), http_req.size());
    TEST_ASSERT(host.has_value(), "HTTP Host extraction succeeded");
    TEST_ASSERT(*host == "example.org", "Host port must be stripped correctly");

    // DNS Query test: query for google.com
    std::vector<uint8_t> dns_pkt = {
        0x12, 0x34, // ID
        0x01, 0x00, // Standard query
        0x00, 0x01, // 1 Question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Question: 6google3com0
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, 0x00, 0x01 // Type A, Class IN
    };

    auto dns_domain = DNSExtractor::extractQuery(dns_pkt.data(), dns_pkt.size());
    TEST_ASSERT(dns_domain.has_value(), "DNS query extraction succeeded");
    TEST_ASSERT(*dns_domain == "google.com", "Extracted domain must match query");
    return true;
}

// Test 7: TLS and QUIC SNI Extraction
bool test_sni_extraction() {
    // Construct valid TLS Client Hello with SNI "test.cloudflare.com"
    std::string sni_str = "test.cloudflare.com";
    std::vector<uint8_t> ch;
    ch.push_back(0x01); // Client Hello
    ch.push_back(0x00); ch.push_back(0x00); ch.push_back(0x00); // 3-byte length placeholder
    ch.push_back(0x03); ch.push_back(0x03); // Version 1.2
    for (int i = 0; i < 32; i++) ch.push_back(static_cast<uint8_t>(i)); // Random
    ch.push_back(0x00); // Session ID len = 0
    ch.push_back(0x00); ch.push_back(0x02); ch.push_back(0x13); ch.push_back(0x01); // 1 cipher suite
    ch.push_back(0x01); ch.push_back(0x00); // 1 compression method (null)

    // Extensions
    std::vector<uint8_t> ext;
    // SNI extension
    ext.push_back(0x00); ext.push_back(0x00); // Type 0x0000 (SNI)
    uint16_t sni_ext_len = 2 + 1 + 2 + static_cast<uint16_t>(sni_str.size());
    ext.push_back(static_cast<uint8_t>((sni_ext_len >> 8) & 0xFF));
    ext.push_back(static_cast<uint8_t>(sni_ext_len & 0xFF));
    
    uint16_t sni_list_len = 1 + 2 + static_cast<uint16_t>(sni_str.size());
    ext.push_back(static_cast<uint8_t>((sni_list_len >> 8) & 0xFF));
    ext.push_back(static_cast<uint8_t>(sni_list_len & 0xFF));
    ext.push_back(0x00); // Hostname type
    ext.push_back(static_cast<uint8_t>((sni_str.size() >> 8) & 0xFF));
    ext.push_back(static_cast<uint8_t>(sni_str.size() & 0xFF));
    for (char c : sni_str) ext.push_back(static_cast<uint8_t>(c));

    // Extensions length header
    uint16_t ext_total_len = static_cast<uint16_t>(ext.size());
    ch.push_back(static_cast<uint8_t>((ext_total_len >> 8) & 0xFF));
    ch.push_back(static_cast<uint8_t>(ext_total_len & 0xFF));
    ch.insert(ch.end(), ext.begin(), ext.end());

    // Update 3-byte handshake length
    uint32_t body_len = static_cast<uint32_t>(ch.size() - 4);
    ch[1] = static_cast<uint8_t>((body_len >> 16) & 0xFF);
    ch[2] = static_cast<uint8_t>((body_len >> 8) & 0xFF);
    ch[3] = static_cast<uint8_t>(body_len & 0xFF);

    // Test direct extraction from Handshake body (QUIC format)
    auto extracted_raw = SNIExtractor::extractFromClientHello(ch.data(), ch.size());
    TEST_ASSERT(extracted_raw.has_value(), "Direct Client Hello extraction must succeed");
    TEST_ASSERT(*extracted_raw == sni_str, "Extracted SNI must match test string");

    // Wrap in TLS Record Layer Header (0x16, 0x03, 0x01, len)
    std::vector<uint8_t> tls_record;
    tls_record.push_back(0x16); // Handshake record
    tls_record.push_back(0x03); tls_record.push_back(0x01);
    uint16_t rec_len = static_cast<uint16_t>(ch.size());
    tls_record.push_back(static_cast<uint8_t>((rec_len >> 8) & 0xFF));
    tls_record.push_back(static_cast<uint8_t>(rec_len & 0xFF));
    tls_record.insert(tls_record.end(), ch.begin(), ch.end());

    auto extracted_tls = SNIExtractor::extract(tls_record.data(), tls_record.size());
    TEST_ASSERT(extracted_tls.has_value(), "TLS Record extraction must succeed");
    TEST_ASSERT(*extracted_tls == sni_str, "Extracted TLS SNI must match");
    return true;
}

// Test 8: Traffic Shaper Token Bucket & QoS Expedited Forwarding
bool test_token_bucket_shaping() {
    ShaperConfig cfg;
    cfg.algorithm = ShaperAlgorithm::TOKEN_BUCKET;
    cfg.rate_limit_pps = 1000.0;
    cfg.burst_capacity = 5.0; // 5 tokens
    cfg.enable_qos_priority = true;

    TrafficShaper shaper(cfg);

    PacketJob normal_job;
    normal_job.packet_id = 1;
    normal_job.tuple.ip_version = 4;
    normal_job.tuple.src_ip = 0x0A000001;
    normal_job.tuple.dst_ip = 0x8EFA0001;
    normal_job.tuple.src_port = 50000;
    normal_job.tuple.dst_port = 80;
    normal_job.tuple.protocol = 6;
    normal_job.tcp_flags = 0x10; // ACK only (not high priority)
    normal_job.data.resize(60, 0);

    // First 5 packets should be admitted immediately as burst
    for (int i = 0; i < 5; ++i) {
        TEST_ASSERT(shaper.canAdmitImmediately(normal_job), "First 5 burst packets should be admitted immediately");
        double delay = shaper.shape(normal_job);
        TEST_ASSERT(delay == 0.0, "Burst packets within capacity should have 0 delay");
    }

    // Now bucket is exhausted, normal packet cannot admit immediately
    TEST_ASSERT(!shaper.canAdmitImmediately(normal_job), "6th packet should exceed burst capacity");

    // But a high-priority QoS packet (e.g. TCP SYN handshake) must bypass shaping delay!
    PacketJob syn_job = normal_job;
    syn_job.tcp_flags = 0x02; // SYN flag
    TEST_ASSERT(shaper.isHighPriority(syn_job), "SYN packet must be recognized as high priority");
    TEST_ASSERT(shaper.canAdmitImmediately(syn_job), "QoS SYN packet should admit immediately even when bucket is empty");
    double syn_delay = shaper.shape(syn_job);
    TEST_ASSERT(syn_delay == 0.0, "QoS SYN packet must have 0 delay");

    // DNS packet (port 53) should also be recognized as high priority
    PacketJob dns_job = normal_job;
    dns_job.tuple.dst_port = 53;
    dns_job.tuple.protocol = 17; // UDP
    dns_job.tcp_flags = 0;
    TEST_ASSERT(shaper.isHighPriority(dns_job), "DNS packet must be recognized as high priority");
    TEST_ASSERT(shaper.canAdmitImmediately(dns_job), "QoS DNS packet should admit immediately even when bucket is empty");
    double dns_delay = shaper.shape(dns_job);
    TEST_ASSERT(dns_delay == 0.0, "QoS DNS packet must have 0 delay");

    auto stats = shaper.getStats();
    TEST_ASSERT(stats.burst_packets == 5, "5 burst packets tracked in stats");
    TEST_ASSERT(stats.high_priority_expedited == 2, "2 QoS high-priority packets expedited");
    return true;
}

// Test 9: Traffic Shaper Leaky Bucket Pacing
bool test_leaky_bucket_pacing() {
    ShaperConfig cfg;
    cfg.algorithm = ShaperAlgorithm::LEAKY_BUCKET;
    cfg.rate_limit_pps = 100.0; // 10ms inter-packet spacing
    cfg.enable_qos_priority = false;

    TrafficShaper shaper(cfg);

    PacketJob job;
    job.packet_id = 1;
    job.tuple.ip_version = 4;
    job.tuple.src_ip = 0x0A000001;
    job.tuple.dst_ip = 0x8EFA0001;
    job.tuple.src_port = 50000;
    job.tuple.dst_port = 80;
    job.tuple.protocol = 6;
    job.data.resize(60, 0);

    TEST_ASSERT(shaper.canAdmitImmediately(job), "First packet in leaky bucket is admitted immediately");
    shaper.shape(job);

    // Immediately after, next packet should NOT be admitted immediately because 10ms hasn't elapsed
    TEST_ASSERT(!shaper.canAdmitImmediately(job), "Immediate second packet must wait for leak interval");

    return true;
}

// Helper to write a small valid PCAP file for testing
static bool write_test_pcap(const std::string& filename,
                            const std::vector<std::pair<uint32_t, uint32_t>>& timestamps,
                            uint8_t host_id) {
    std::ofstream f(filename, std::ios::binary);
    if (!f.is_open()) return false;

    PcapGlobalHeader gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1;
    f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    std::vector<uint8_t> pkt_data = {
        // Ethernet (14)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        10, 0, 0, host_id,
        142, 250, 0, 1,
        // TCP (20)
        0x1F, 0x90, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xFA, 0xF0,
        0x00, 0x00, 0x00, 0x00
    };

    for (const auto& ts : timestamps) {
        PcapPacketHeader ph;
        ph.ts_sec = ts.first;
        ph.ts_usec = ts.second;
        ph.incl_len = static_cast<uint32_t>(pkt_data.size());
        ph.orig_len = static_cast<uint32_t>(pkt_data.size());
        f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        f.write(reinterpret_cast<const char*>(pkt_data.data()), pkt_data.size());
    }
    f.close();
    return true;
}

// Test 10: Multi-PCAP Orchestration & Chronological Min-Heap Merging
bool test_multi_pcap_orchestrated_merge() {
    std::string file1 = "/tmp/test_host1.pcap";
    std::string file2 = "/tmp/test_host2.pcap";

    // Host 1: packets at t = 100s and 300s
    std::vector<std::pair<uint32_t, uint32_t>> ts1 = {{100, 0}, {300, 0}};
    // Host 2: packets at t = 200s and 400s
    std::vector<std::pair<uint32_t, uint32_t>> ts2 = {{200, 0}, {400, 0}};

    TEST_ASSERT(write_test_pcap(file1, ts1, 1), "Write host1 pcap succeeds");
    TEST_ASSERT(write_test_pcap(file2, ts2, 2), "Write host2 pcap succeeds");

    OrchestratorConfig cfg;
    cfg.ingestion_mode = IngestionMode::CHRONOLOGICAL_MERGE;
    cfg.shaper_config.algorithm = ShaperAlgorithm::NONE;

    TrafficOrchestrator orch(cfg);
    TEST_ASSERT(orch.addSource(file1), "Add source host1");
    TEST_ASSERT(orch.addSource(file2), "Add source host2");

    std::vector<uint32_t> merged_timestamps;
    std::atomic<bool> running{true};

    orch.run(running, nullptr, [&](const PacketJob& job) {
        merged_timestamps.push_back(job.ts_sec);
    });

    TEST_ASSERT(merged_timestamps.size() == 4, "All 4 packets must be merged and dispatched");
    TEST_ASSERT(merged_timestamps[0] == 100, "1st packet timestamp 100");
    TEST_ASSERT(merged_timestamps[1] == 200, "2nd packet timestamp 200");
    TEST_ASSERT(merged_timestamps[2] == 300, "3rd packet timestamp 300");
    TEST_ASSERT(merged_timestamps[3] == 400, "4th packet timestamp 400");

    std::remove(file1.c_str());
    std::remove(file2.c_str());
    return true;
}

// Test 11: Multi-Queue Capture Interface with Least-Loaded Shard Routing
bool test_multiqueue_capture_least_loaded() {
    std::string s0 = "/tmp/mq_test_shard_0.pcap";
    std::string s1 = "/tmp/mq_test_shard_1.pcap";

    MultiQueueCaptureConfig cfg;
    cfg.num_shards = 2;
    cfg.routing_policy = ShardRoutingPolicy::LEAST_LOADED;
    cfg.shaper_config.algorithm = ShaperAlgorithm::NONE;

    MultiQueueCaptureInterface mq(cfg);

    PcapGlobalHeader gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1;

    std::vector<std::string> shard_files = {s0, s1};
    TEST_ASSERT(mq.initialize(shard_files, gh), "Initialize 2 shards must succeed");

    PacketJob job1;
    job1.packet_id = 1;
    job1.ts_sec = 1000;
    job1.ts_usec = 10;
    job1.tuple.ip_version = 4;
    job1.tuple.src_ip = 0x0A000001;
    job1.tuple.dst_ip = 0x01010101;
    job1.data.resize(60, 0);

    PacketJob job2 = job1;
    job2.packet_id = 2;

    TEST_ASSERT(mq.dispatch(job1), "Dispatch job 1");
    TEST_ASSERT(mq.dispatch(job2), "Dispatch job 2");

    mq.close();

    std::ifstream f0(s0, std::ios::binary);
    std::ifstream f1(s1, std::ios::binary);
    TEST_ASSERT(f0.is_open(), "Shard 0 file must exist");
    TEST_ASSERT(f1.is_open(), "Shard 1 file must exist");

    f0.close();
    f1.close();
    std::remove(s0.c_str());
    std::remove(s1.c_str());
    return true;
}

// Test 12: Multi-Queue Capture Interface with Flow Affinity (Bidirectional pinning)
bool test_multiqueue_capture_flow_affinity() {
    std::string s0 = "/tmp/mq_affinity_0.pcap";
    std::string s1 = "/tmp/mq_affinity_1.pcap";

    MultiQueueCaptureConfig cfg;
    cfg.num_shards = 2;
    cfg.routing_policy = ShardRoutingPolicy::FLOW_AFFINITY;
    cfg.shaper_config.algorithm = ShaperAlgorithm::NONE;

    MultiQueueCaptureInterface mq(cfg);

    PcapGlobalHeader gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1;

    std::vector<std::string> shard_files = {s0, s1};
    TEST_ASSERT(mq.initialize(shard_files, gh), "Initialize 2 shards for affinity");

    FiveTuple flow_fwd;
    flow_fwd.ip_version = 4;
    flow_fwd.src_ip = 0x0A000005;
    flow_fwd.dst_ip = 0x8EFA0001;
    flow_fwd.src_port = 54321;
    flow_fwd.dst_port = 443;
    flow_fwd.protocol = 6;

    FiveTuple flow_rev = flow_fwd.reverse();

    FiveTupleHash hasher;
    size_t target_shard = hasher(flow_fwd) % 2;
    size_t rev_shard = hasher(flow_rev) % 2;

    TEST_ASSERT(target_shard == rev_shard, "Symmetric hash guarantees same shard index for forward and reverse flow");

    PacketJob pkt_fwd;
    pkt_fwd.packet_id = 1;
    pkt_fwd.ts_sec = 1000;
    pkt_fwd.ts_usec = 10;
    pkt_fwd.tuple = flow_fwd;
    pkt_fwd.data.resize(54, 0);

    PacketJob pkt_rev = pkt_fwd;
    pkt_rev.packet_id = 2;
    pkt_rev.tuple = flow_rev;

    TEST_ASSERT(mq.dispatch(pkt_fwd), "Dispatch forward packet");
    TEST_ASSERT(mq.dispatch(pkt_rev), "Dispatch reverse packet");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto stats = mq.getAllShardStats();
    mq.close();

    TEST_ASSERT(stats[target_shard].packets_written == 2, "Target shard must receive both bidirectional packets");
    TEST_ASSERT(stats[1 - target_shard].packets_written == 0, "Opposite shard must receive 0 packets of this flow");

    std::remove(s0.c_str());
    std::remove(s1.c_str());
    return true;
}

// Test 13: Aho-Corasick Multi-Pattern Search Automaton (Wire-Speed L7 Matching)
bool test_aho_corasick_automaton() {
    AhoCorasick ac(false); // Case-insensitive
    ac.addPattern("he", "P1");
    ac.addPattern("she", "P2");
    ac.addPattern("his", "P3");
    ac.addPattern("hers", "P4");
    ac.build();

    TEST_ASSERT(ac.isBuilt(), "Automaton must be built");
    TEST_ASSERT(ac.patternCount() == 4, "Must hold 4 patterns");

    std::string text = "ushers";
    auto matches = ac.searchAll(reinterpret_cast<const uint8_t*>(text.data()), text.size());

    TEST_ASSERT(matches.size() >= 3, "Must find at least 3 overlapping pattern occurrences");

    bool found_she = false;
    bool found_he = false;
    bool found_hers = false;
    for (const auto& m : matches) {
        if (m.name == "P2") found_she = true;
        if (m.name == "P1") found_he = true;
        if (m.name == "P4") found_hers = true;
    }

    TEST_ASSERT(found_she, "Must find 'she'");
    TEST_ASSERT(found_he, "Must find 'he'");
    TEST_ASSERT(found_hers, "Must find 'hers'");

    PatternMatch first;
    TEST_ASSERT(ac.findFirst(text, &first), "findFirst must return true");
    TEST_ASSERT(first.name == "P2" || first.name == "P1", "First match must be she or he");

    TEST_ASSERT(!ac.findFirst("xyz123", nullptr), "Non-matching payload must return false");
    return true;
}

// Test 14: L7 Deep Payload Inspection & NIDS Attack Signature Blocking
bool test_l7_payload_inspection_rule_manager() {
    RuleManager rm;
    rm.loadDefaultNIDSSignatures();

    // Normal benign payload
    std::string benign = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    auto b_res = rm.shouldBlock(
        0x0A000001,
        80,
        AppType::HTTP,
        "example.com",
        reinterpret_cast<const uint8_t*>(benign.data()),
        benign.size()
    );
    TEST_ASSERT(!b_res.has_value(), "Benign HTTP traffic must not be blocked");

    // Malicious SQL Injection payload
    std::string sqli = "GET /search?q=admin' UNION SELECT password, username FROM users-- HTTP/1.1\r\nHost: target.com\r\n\r\n";
    auto sqli_res = rm.shouldBlock(
        0x0A000001,
        80,
        AppType::HTTP,
        "target.com",
        reinterpret_cast<const uint8_t*>(sqli.data()),
        sqli.size()
    );
    TEST_ASSERT(sqli_res.has_value(), "SQLi payload must be blocked");
    TEST_ASSERT(sqli_res->type == RuleManager::BlockReason::Type::PAYLOAD_SIGNATURE, "Block reason must be PAYLOAD_SIGNATURE");

    // Malicious RCE Shellcode payload
    std::string rce = "POST /api/exec HTTP/1.1\r\nContent-Length: 20\r\n\r\n; /bin/sh -c 'id'";
    auto rce_res = rm.shouldBlock(
        0x0A000001,
        8080,
        AppType::HTTP,
        "internal.api",
        reinterpret_cast<const uint8_t*>(rce.data()),
        rce.size()
    );
    TEST_ASSERT(rce_res.has_value(), "RCE payload must be blocked");
    TEST_ASSERT(rce_res->type == RuleManager::BlockReason::Type::PAYLOAD_SIGNATURE, "RCE reason must be PAYLOAD_SIGNATURE");

    return true;
}

// Test 15: Shannon Entropy & Core Domain Extraction
bool test_shannon_entropy_calculation() {
    double ent_single = SecurityAnalyzer::calculateShannonEntropy("aaaaaa");
    TEST_ASSERT(ent_single == 0.0, "Identical chars must have 0.0 entropy");

    double ent_benign = SecurityAnalyzer::calculateShannonEntropy("google");
    TEST_ASSERT(ent_benign > 1.8 && ent_benign < 2.5, "Natural domain words have moderate entropy");

    double ent_random = SecurityAnalyzer::calculateShannonEntropy("w9x1k8p3q7z2m4b0");
    TEST_ASSERT(ent_random >= 3.6, "Uniform pseudo-random strings have high entropy (>= 3.6)");

    std::string core1 = SecurityAnalyzer::extractCoreDomain("subdomain.target.com");
    TEST_ASSERT(core1 == "target", "Core domain extraction must isolate SLD");

    std::string core2 = SecurityAnalyzer::extractCoreDomain("malware-c2.co.uk");
    TEST_ASSERT(core2 == "malware-c2", "Core domain extraction must handle compound ccTLDs");

    return true;
}

// Test 16: DGA Domain Classifier
bool test_dga_domain_classification() {
    SecurityAnalyzer sa(3.6);

    auto dga_neg1 = sa.analyzeDomain("api.github.com");
    TEST_ASSERT(!dga_neg1.is_dga, "Legitimate domains must not be classified as DGA");

    auto dga_neg2 = sa.analyzeDomain("login.microsoftonline.com");
    TEST_ASSERT(!dga_neg2.is_dga, "Standard corporate domains must not be classified as DGA");

    // Conficker/CryptoLocker style pseudo-random algorithmically generated domain
    auto dga_pos = sa.analyzeDomain("v8n3q1z9k7x2p4m0.biz");
    TEST_ASSERT(dga_pos.is_dga, "High-entropy pseudo-random domain must be classified as DGA");
    TEST_ASSERT(dga_pos.entropy >= 3.6, "DGA entropy must meet threshold");

    return true;
}

// Test 17: DNS Tunneling & Data Exfiltration Detector
bool test_dns_tunneling_detection() {
    SecurityAnalyzer sa;

    // Normal DNS lookup
    auto dns_norm = sa.analyzeDNSQuery("mail.google.com");
    TEST_ASSERT(!dns_norm.is_tunneling, "Normal DNS query must not be flagged as tunneling");

    // Hex-encoded DNS exfiltration tunnel
    auto dns_hex = sa.analyzeDNSQuery("48656c6c6f576f726c6453656372657444617461457866696c74726174696f6e.tunnel.attacker.com");
    TEST_ASSERT(dns_hex.is_tunneling, "Hex exfiltration label must be flagged as DNS tunneling");
    TEST_ASSERT(dns_hex.hex_or_b64_ratio >= 0.8, "Hex density ratio should be high");

    // Base64-encoded DNS covert channel
    auto dns_b64 = sa.analyzeDNSQuery("dGhpcy1pcy1hLXNlY3JldC1leGZpbHRyYXRpb24tcGF5bG9hZC12aWEtZG5z.c2.evil.org");
    TEST_ASSERT(dns_b64.is_tunneling, "Base64 exfiltration label must be flagged as DNS tunneling");

    return true;
}

// Test 18: Passive TCP SYN OS Fingerprinting
bool test_passive_os_fingerprinting() {
    // macOS / iOS: initial TTL 64, window 65535
    auto mac_fp = SecurityAnalyzer::fingerprintTCPSYN(64, 65535, 0x02);
    TEST_ASSERT(mac_fp.os_family == "macOS / iOS", "macOS fingerprint failed");
    TEST_ASSERT(mac_fp.estimated_hops == 0, "Direct hop count should be 0");

    // Linux: initial TTL 64, window 29200 (or routed with TTL 62, hops 2)
    auto linux_fp = SecurityAnalyzer::fingerprintTCPSYN(62, 29200, 0x02);
    TEST_ASSERT(linux_fp.os_family == "Linux / Android", "Linux fingerprint failed");
    TEST_ASSERT(linux_fp.estimated_hops == 2, "Linux estimated hops should be 2");

    // Windows: initial TTL 128, window 64240 (or routed with TTL 120, hops 8)
    auto win_fp = SecurityAnalyzer::fingerprintTCPSYN(120, 64240, 0x02);
    TEST_ASSERT(win_fp.os_family == "Windows", "Windows fingerprint failed");
    TEST_ASSERT(win_fp.estimated_hops == 8, "Windows estimated hops should be 8");

    // Cisco / Network equipment: initial TTL 255
    auto net_fp = SecurityAnalyzer::fingerprintTCPSYN(250, 4128, 0x02);
    TEST_ASSERT(net_fp.os_family == "Network Equipment / BSD", "Network equipment fingerprint failed");
    TEST_ASSERT(net_fp.estimated_hops == 5, "Network equipment hops should be 5");

    return true;
}

// Test 19: Per-Flow Micro-Token Bucket & Hierarchical Bandwidth Quota
bool test_micro_token_bucket_flow_shaping() {
    MicroTokenBucket bucket;
    bucket.configure(1000.0, 2000.0); // 1000 bytes/sec, 2000 bytes burst capacity
    bucket.tokens = 2000.0; // Start with full bucket

    auto now = std::chrono::steady_clock::now();

    // 1. Consume 1500 bytes: should succeed
    bool ok1 = bucket.consume(1500, now);
    TEST_ASSERT(ok1, "Initial burst under capacity must succeed");
    TEST_ASSERT(bucket.tokens == 500.0, "Remaining tokens must equal 500");

    // 2. Immediately try consuming 1000 bytes: only 500 available, should be throttled
    bool ok2 = bucket.consume(1000, now);
    TEST_ASSERT(!ok2, "Exceeding available burst quota must fail immediately");

    // 3. Fast-forward time by 1.0 second: 1000 tokens should be refilled (500 + 1000 = 1500)
    auto future_time = now + std::chrono::milliseconds(1000);
    bool ok3 = bucket.consume(1000, future_time);
    TEST_ASSERT(ok3, "Tokens refilled after 1 second must allow packet consumption");
    TEST_ASSERT(bucket.tokens >= 490.0 && bucket.tokens <= 510.0, "Tokens accurately deducted post-refill");

    // 4. Test RuleManager Flow Policy
    RuleManager rm;
    rm.setDefaultFlowRateLimit(500000.0, 65536.0); // 500 KB/s default
    rm.setAppFlowRateLimit(AppType::YOUTUBE, 200000.0, 32768.0); // 200 KB/s for YouTube

    Connection c_gen;
    c_gen.app_type = AppType::HTTP;
    rm.applyFlowPolicy(&c_gen);
    TEST_ASSERT(c_gen.flow_bucket.rate_bps == 500000.0, "Default policy must apply to non-specific apps");

    Connection c_yt;
    c_yt.app_type = AppType::YOUTUBE;
    rm.applyFlowPolicy(&c_yt);
    TEST_ASSERT(c_yt.flow_bucket.rate_bps == 200000.0, "App-specific policy must override default policy");

    return true;
}

// Test 20: Real-Time Live ANSI Cyber-Ops TUI Dashboard Rendering
bool test_ansi_tui_dashboard_rendering() {
    DPIStats stats;
    stats.total_packets = 5000;
    stats.forwarded_packets = 4950;
    stats.dropped_packets = 50;
    stats.tcp_packets = 4500;
    stats.udp_packets = 500;
    stats.total_bytes = 1048576;

    std::string rendered = TUIDashboard::render(
        stats,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        false
    );

    TEST_ASSERT(!rendered.empty(), "Dashboard render must produce non-empty ANSI string");
    TEST_ASSERT(rendered.find("DEEP PACKET ANALYZER") != std::string::npos, "Dashboard must contain header banner");
    TEST_ASSERT(rendered.find("INGESTION & THROUGHPUT TELEMETRY") != std::string::npos, "Dashboard must contain telemetry section");
    TEST_ASSERT(rendered.find("5000") != std::string::npos, "Dashboard must display total packet count");
    TEST_ASSERT(rendered.find("1.00%") != std::string::npos, "Dashboard must display correct 1.00% drop rate");

    return true;
}

int main() {
    std::cout << "\n=========================================\n";
    std::cout << "   DPI ENGINE COMPREHENSIVE TEST SUITE   \n";
    std::cout << "=========================================\n\n";

    int passed = 0;
    int failed = 0;

    RUN_TEST(test_five_tuple_symmetry);
    RUN_TEST(test_domain_matching_precision);
    RUN_TEST(test_load_balancer_distribution);
    RUN_TEST(test_rule_manager_cidr_and_wildcards);
    RUN_TEST(test_connection_tracker_bidirectional);
    RUN_TEST(test_http_and_dns_extraction);
    RUN_TEST(test_sni_extraction);
    RUN_TEST(test_token_bucket_shaping);
    RUN_TEST(test_leaky_bucket_pacing);
    RUN_TEST(test_multi_pcap_orchestrated_merge);
    RUN_TEST(test_multiqueue_capture_least_loaded);
    RUN_TEST(test_multiqueue_capture_flow_affinity);
    RUN_TEST(test_aho_corasick_automaton);
    RUN_TEST(test_l7_payload_inspection_rule_manager);
    RUN_TEST(test_shannon_entropy_calculation);
    RUN_TEST(test_dga_domain_classification);
    RUN_TEST(test_dns_tunneling_detection);
    RUN_TEST(test_passive_os_fingerprinting);
    RUN_TEST(test_micro_token_bucket_flow_shaping);
    RUN_TEST(test_ansi_tui_dashboard_rendering);

    std::cout << "\n=========================================\n";
    std::cout << "Result: " << passed << " passed, " << failed << " failed\n";
    std::cout << "=========================================\n\n";

    return failed == 0 ? 0 : 1;
}

