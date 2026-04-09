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
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/Core/ui)

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
    ${CMAKE_SOURCE_DIR}/Core          # so #include "Types.h" works everywhere
    ${CMAKE_SOURCE_DIR}              # so #include "Core/ui/MainWindow.h" works from main.cpp
)

# ─── Sources ──────────────────────────────────────────────────────────────────
set(SOURCES
    # Entry point
    main.cpp

    # Capture
    Core/capture/PacketCapture.cpp
    Core/capture/NetlinkReceiver.cpp

    # Parser
    Core/parser/PacketParser.cpp

    # Flow
    Core/flow/FlowTracker.cpp
    Core/flow/FlowTable.cpp

    # Features
    Core/features/FeatureExtractor.cpp
    Core/features/FeatureNormalizer.cpp

    # Detection
    Core/detection/RuleEngine.cpp
    Core/detection/DecisionEngine.cpp
    Core/detection/AdaptiveThreshold.cpp

    # ML
    Core/ml/MLBridge.cpp
    Core/ml/MLResultCache.cpp

    # Metrics
    Core/metrics/PerformanceMonitor.cpp

    # Pipeline
    Core/pipeline/ProcessingPipeline.cpp

    # UI
    Core/ui/MainWindow.cpp
    Core/ui/TrafficPanel.cpp
    Core/ui/TrafficChart.cpp
    Core/ui/AlertsPanel.cpp
    Core/ui/SuspiciousIPTable.cpp
    Core/ui/LogsViewer.cpp
    Core/ui/MetricsBar.cpp
    Core/ui/UIBridge.cpp
)

# ─── Headers (listed so IDEs and AUTOMOC pick them up) ───────────────────────
set(HEADERS
    Core/Types.h

    Core/capture/PacketCapture.h
    Core/capture/NetlinkReceiver.h

    Core/parser/PacketParser.h

    Core/flow/FlowTracker.h
    Core/flow/FlowTable.h

    Core/features/FeatureExtractor.h
    Core/features/FeatureNormalizer.h

    Core/detection/RuleEngine.h
    Core/detection/DecisionEngine.h
    Core/detection/AdaptiveThreshold.h

    Core/ml/MLBridge.h
    Core/ml/MLResultCache.h

    Core/metrics/PerformanceMonitor.h
    Core/metrics/SystemStats.h

    Core/pipeline/ProcessingPipeline.h
    Core/pipeline/PacketQueue.h

    Core/ui/MainWindow.h
    Core/ui/TrafficPanel.h
    Core/ui/TrafficChart.h
    Core/ui/AlertsPanel.h
    Core/ui/SuspiciousIPTable.h
    Core/ui/LogsViewer.h
    Core/ui/MetricsBar.h
    Core/ui/UIBridge.h
)

# ─── UI files (Qt Designer .ui → ui_*.h via AUTOUIC) ─────────────────────────
set(UI_FILES
    Core/ui/MainWindow.ui
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
    set(TEST_COMMON_CoreS
        Core/parser/PacketParser.cpp
        Core/flow/FlowTracker.cpp
        Core/flow/FlowTable.cpp
        Core/detection/RuleEngine.cpp
        Core/detection/AdaptiveThreshold.cpp
        Core/features/FeatureExtractor.cpp
        Core/features/FeatureNormalizer.cpp
    )

    # test_parser
    add_executable(test_parser
        tests/test_parser.cpp
        Core/parser/PacketParser.cpp
    )
    target_include_directories(test_parser PRIVATE
        ${CMAKE_SOURCE_DIR}/Core
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(test_parser Qt6::Core)
    target_compile_options(test_parser PRIVATE -Wall -Wextra)
    add_test(NAME ParserTest COMMAND test_parser)

    # test_flow
    add_executable(test_flow
        tests/test_flow.cpp
        Core/flow/FlowTracker.cpp
        Core/flow/FlowTable.cpp
    )
    target_include_directories(test_flow PRIVATE
        ${CMAKE_SOURCE_DIR}/Core
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(test_flow Qt6::Core pthread)
    target_compile_options(test_flow PRIVATE -Wall -Wextra)
    add_test(NAME FlowTest COMMAND test_flow)

    # test_rules
    add_executable(test_rules
        tests/test_rules.cpp
        Core/detection/RuleEngine.cpp
        Core/detection/AdaptiveThreshold.cpp
    )
    target_include_directories(test_rules PRIVATE
        ${CMAKE_SOURCE_DIR}/Core
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