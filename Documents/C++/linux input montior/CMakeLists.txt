cmake_minimum_required(VERSION 3.10)

project(linux_input_monitor
    VERSION 1.0
    DESCRIPTION "Linux input event monitor"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra)

add_executable(input-monitor
    src/main.cpp
    src/device.cpp
    src/event_reader.cpp
    src/event_printer.cpp
)

target_include_directories(input-monitor
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)
