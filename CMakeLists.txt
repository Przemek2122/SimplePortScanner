cmake_minimum_required(VERSION 3.14)
project(PortScanner CXX)

# Enforce C++20 for std::jthread and std::stop_token
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable strict compiler warnings for deep logic and syntax verification
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")

# Fetch the custom INI library from GitHub
include(FetchContent)
FetchContent_Declare(
    sqrll_ini_reader
    GIT_REPOSITORY https://github.com/Przemek2122/SQRLL_INI_Reader.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(sqrll_ini_reader)

# Define the main executable
add_executable(port_scanner main.cpp)

# Find system threading library safely
find_package(Threads REQUIRED)

# Link the executable with required dependencies
# Note: If your library uses a different target name in its own CMakeLists.txt, 
# update 'sqrll_ini_reader' below to match it.
target_link_libraries(port_scanner 
    PRIVATE 
    Threads::Threads 
    IniReader
)