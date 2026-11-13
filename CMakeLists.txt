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
    src/types.cpp
    src/aho_corasick.cpp
    src/security_analyzer.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/traffic_shaper.cpp
    src/traffic_orchestrator.cpp
    src/multiqueue_pcap_writer.cpp
    src/tui_dashboard.cpp
    src/dpi_engine.cpp
)

add_library(dpi_core STATIC ${DPI_CORE_SOURCES})
target_link_libraries(dpi_core PUBLIC Threads::Threads)

# ==========================================
# Main DPI Engine Executable
# ==========================================
add_executable(dpi_engine src/main_dpi.cpp)
target_link_libraries(dpi_engine PRIVATE dpi_core Threads::Threads)

# ==========================================
# Packet Analyzer Diagnostic Utility
# ==========================================
add_executable(packet_analyzer src/main.cpp)
target_link_libraries(packet_analyzer PRIVATE dpi_core)

# ==========================================
# Automated Test Suite
# ==========================================
enable_testing()
add_executable(dpi_tests tests/test_main.cpp)
target_link_libraries(dpi_tests PRIVATE dpi_core Threads::Threads)
add_test(NAME DPIUnitTests COMMAND dpi_tests)
