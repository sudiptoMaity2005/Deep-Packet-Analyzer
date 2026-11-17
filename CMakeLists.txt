cmake_minimum_required(VERSION 3.16)
project(DeepPacketAnalyzer VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler optimization and warnings
if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

find_package(Threads REQUIRED)

# ==========================================
# Include Directories
# ==========================================
include_directories(${CMAKE_SOURCE_DIR}/include)

# ==========================================
# Core DPI Static Library
# ==========================================
set(DPI_CORE_SOURCES
    # Core Engine & Concurrency
    src/core/types.cpp
    src/core/connection_tracker.cpp
    src/core/fast_path.cpp
    src/core/load_balancer.cpp
    src/core/dpi_engine.cpp

    # Protocol Parsers & SNI Extractors
    src/protocol/pcap_reader.cpp
    src/protocol/packet_parser.cpp
    src/protocol/sni_extractor.cpp

    # Security Intelligence & NIDS
    src/security/aho_corasick.cpp
    src/security/security_analyzer.cpp
    src/security/rule_manager.cpp

    # Traffic Orchestration, Shaping & Multi-Queue Storage
    src/traffic/traffic_shaper.cpp
    src/traffic/traffic_orchestrator.cpp
    src/traffic/multiqueue_pcap_writer.cpp

    # Cyber-Ops Terminal UI Dashboard
    src/ui/tui_dashboard.cpp
)

add_library(dpi_core STATIC ${DPI_CORE_SOURCES})
target_link_libraries(dpi_core PUBLIC Threads::Threads)

# ==========================================
# Main DPI Engine Executable
# ==========================================
add_executable(dpi_engine src/app/main_dpi.cpp)
target_link_libraries(dpi_engine PRIVATE dpi_core Threads::Threads)

# ==========================================
# Packet Analyzer Diagnostic Utility
# ==========================================
add_executable(packet_analyzer src/app/main.cpp)
target_link_libraries(packet_analyzer PRIVATE dpi_core)

# ==========================================
# Automated Test Suite
# ==========================================
enable_testing()
add_executable(dpi_tests tests/test_main.cpp)
target_link_libraries(dpi_tests PRIVATE dpi_core Threads::Threads)
add_test(NAME DPIUnitTests COMMAND dpi_tests)
