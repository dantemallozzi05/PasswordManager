cmake_minimum_required(VERSION 3.20)
project(PasswordManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies (from vcpkg)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# Executable
add_executable(PasswordManager
    PasswordManager.cpp
    src/crypto.cpp 
)

# Link libraries
target_link_libraries(PasswordManager PRIVATE
    unofficial-sodium::sodium
    nlohmann_json::nlohmann_json
)
