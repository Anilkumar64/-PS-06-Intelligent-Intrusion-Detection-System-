cmake_minimum_required(VERSION 3.20)
project(IDS_System VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt6 packages
find_package(Qt6 REQUIRED COMPONENTS
    Core Widgets Charts Network
)

# libpcap
find_library(PCAP_LIBRARY pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)

# Python3 (for ML module)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

include_directories(
    ${PCAP_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

set(SOURCES
    src/main.cpp

    # Capture
    src/capture/PacketCapture.cpp

    # Parser
    src/parser/PacketParser.cpp

    # Flow
    src/flow/FlowTracker.cpp

    # Features
    src/features/FeatureExtractor.cpp

    # Detection
    src/detection/RuleEngine.cpp
    src/detection/DecisionEngine.cpp

    # ML Bridge
    src/ml/MLBridge.cpp

    # UI
    src/ui/MainWindow.cpp
    src/ui/AlertDelegate.cpp
    src/ui/StatusDelegate.cpp
    src/ui/TrafficChart.cpp
)

set(HEADERS
    src/Types.h
    src/capture/PacketCapture.h
    src/parser/PacketParser.h
    src/flow/FlowTracker.h
    src/features/FeatureExtractor.h
    src/detection/RuleEngine.h
    src/detection/DecisionEngine.h
    src/ml/MLBridge.h
    src/ui/MainWindow.h
    src/ui/AlertDelegate.h
    src/ui/StatusDelegate.h
    src/ui/TrafficChart.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME}
    Qt6::Core
    Qt6::Widgets
    Qt6::Charts
    Qt6::Network
    ${PCAP_LIBRARY}
    pthread
)

# Copy Python ML script next to the binary
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/ml/ml_scorer.py
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/ml_scorer.py
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES ml/ml_scorer.py DESTINATION bin)