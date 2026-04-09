cmake_minimum_required(VERSION 3.20)
project(IDS_System VERSION 1.0.0 LANGUAGES CXX)

# ─── C++ standard ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Qt MOC / UIC / RCC auto-generation ──────────────────────────────────────
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Tell AUTOUIC where to find .ui files
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/src/ui)

# ─── Build type default ───────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# ─── Qt6 ──────────────────────────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Charts Network)
message(STATUS "Qt6 version: ${Qt6_VERSION}")

# ─── libpcap ──────────────────────────────────────────────────────────────────
find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h REQUIRED)

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt install libpcap-dev")
endif()
message(STATUS "libpcap: ${PCAP_LIBRARY}")

# ─── Python3 (runtime only — used for ML subprocess) ─────────────────────────
find_package(Python3 COMPONENTS Interpreter REQUIRED)
message(STATUS "Python3: ${Python3_EXECUTABLE}")

# ─── Include paths ────────────────────────────────────────────────────────────
include_directories(
    ${PCAP_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src          # so #include "Types.h" works everywhere
    ${CMAKE_SOURCE_DIR}              # so #include "src/ui/MainWindow.h" works from main.cpp
)

# ─── Sources ──────────────────────────────────────────────────────────────────
set(SOURCES
    # Entry point
    main.cpp

    # Capture
    src/capture/PacketCapture.cpp
    src/capture/NetlinkReceiver.cpp

    # Parser
    src/parser/PacketParser.cpp

    # Flow
    src/flow/FlowTracker.cpp
    src/flow/FlowTable.cpp

    # Features
    src/features/FeatureExtractor.cpp
    src/features/FeatureNormalizer.cpp

    # Detection
    src/detection/RuleEngine.cpp
    src/detection/DecisionEngine.cpp
    src/detection/AdaptiveThreshold.cpp

    # ML
    src/ml/MLBridge.cpp
    src/ml/MLResultCache.cpp

    # Metrics
    src/metrics/PerformanceMonitor.cpp

    # Pipeline
    src/pipeline/ProcessingPipeline.cpp

    # UI
    src/ui/MainWindow.cpp
    src/ui/TrafficPanel.cpp
    src/ui/TrafficChart.cpp
    src/ui/AlertsPanel.cpp
    src/ui/SuspiciousIPTable.cpp
    src/ui/LogsViewer.cpp
    src/ui/MetricsBar.cpp
    src/ui/UIBridge.cpp
)

# ─── Headers (listed so IDEs and AUTOMOC pick them up) ───────────────────────
set(HEADERS
    src/Types.h

    src/capture/PacketCapture.h
    src/capture/NetlinkReceiver.h

    src/parser/PacketParser.h

    src/flow/FlowTracker.h
    src/flow/FlowTable.h

    src/features/FeatureExtractor.h
    src/features/FeatureNormalizer.h

    src/detection/RuleEngine.h
    src/detection/DecisionEngine.h
    src/detection/AdaptiveThreshold.h

    src/ml/MLBridge.h
    src/ml/MLResultCache.h

    src/metrics/PerformanceMonitor.h
    src/metrics/SystemStats.h

    src/pipeline/ProcessingPipeline.h
    src/pipeline/PacketQueue.h

    src/ui/MainWindow.h
    src/ui/TrafficPanel.h
    src/ui/TrafficChart.h
    src/ui/AlertsPanel.h
    src/ui/SuspiciousIPTable.h
    src/ui/LogsViewer.h
    src/ui/MetricsBar.h
    src/ui/UIBridge.h
)

# ─── UI files (Qt Designer .ui → ui_*.h via AUTOUIC) ─────────────────────────
set(UI_FILES
    src/ui/MainWindow.ui
)

# ─── Executable ───────────────────────────────────────────────────────────────
add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    ${UI_FILES}
)

# ─── Compiler options ─────────────────────────────────────────────────────────
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g -O0>
)

# ─── Link libraries ───────────────────────────────────────────────────────────
target_link_libraries(${PROJECT_NAME}
    Qt6::Core
    Qt6::Widgets
    Qt6::Charts
    Qt6::Network
    ${PCAP_LIBRARY}
    pthread
)

# ─── Post-build: copy Python ML scorer next to binary ─────────────────────────
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/ml/ml_scorer.py
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/ml_scorer.py
    COMMENT "Copying ml_scorer.py next to binary"
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/ml/train_model.py
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/train_model.py
    COMMENT "Copying train_model.py next to binary"
)

# ─── Install ──────────────────────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES
    ml/ml_scorer.py
    ml/train_model.py
    ml/requirements.txt
    DESTINATION bin
)

# ─── Optional: unit test targets ──────────────────────────────────────────────
option(BUILD_TESTS "Build unit test binaries" OFF)

if(BUILD_TESTS)
    enable_testing()

    # Shared test support sources
    set(TEST_COMMON_SRCS
        src/parser/PacketParser.cpp
        src/flow/FlowTracker.cpp
        src/flow/FlowTable.cpp
        src/detection/RuleEngine.cpp
        src/detection/AdaptiveThreshold.cpp
        src/features/FeatureExtractor.cpp
        src/features/FeatureNormalizer.cpp
    )

    # test_parser
    add_executable(test_parser
        tests/test_parser.cpp
        src/parser/PacketParser.cpp
    )
    target_include_directories(test_parser PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(test_parser Qt6::Core)
    target_compile_options(test_parser PRIVATE -Wall -Wextra)
    add_test(NAME ParserTest COMMAND test_parser)

    # test_flow
    add_executable(test_flow
        tests/test_flow.cpp
        src/flow/FlowTracker.cpp
        src/flow/FlowTable.cpp
    )
    target_include_directories(test_flow PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(test_flow Qt6::Core pthread)
    target_compile_options(test_flow PRIVATE -Wall -Wextra)
    add_test(NAME FlowTest COMMAND test_flow)

    # test_rules
    add_executable(test_rules
        tests/test_rules.cpp
        src/detection/RuleEngine.cpp
        src/detection/AdaptiveThreshold.cpp
    )
    target_include_directories(test_rules PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(test_rules Qt6::Core)
    target_compile_options(test_rules PRIVATE -Wall -Wextra)
    add_test(NAME RulesTest COMMAND test_rules)
endif()

# ─── Summary ──────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║        IDS_System build configured       ║")
message(STATUS "╠══════════════════════════════════════════╣")
message(STATUS "║  Qt6       : ${Qt6_VERSION}")
message(STATUS "║  libpcap   : ${PCAP_LIBRARY}")
message(STATUS "║  Python3   : ${Python3_EXECUTABLE}")
message(STATUS "║  Build     : ${CMAKE_BUILD_TYPE}")
message(STATUS "║  Tests     : ${BUILD_TESTS}")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
message(STATUS "Build with:")
message(STATUS "  mkdir build && cd build")
message(STATUS "  cmake .. -DCMAKE_BUILD_TYPE=Release")
message(STATUS "  make -j\$(nproc)")
message(STATUS "  sudo ./IDS_System")