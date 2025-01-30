cmake_minimum_required(VERSION 3.30)
project(qtGG-crypto)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL)
find_package(nlohmann_json REQUIRED)

include_directories(include/crypto)

add_library(qtGG-crypto STATIC
        src/Crypt.cpp
        include/crypto/Crypt.hpp
        src/Jwt.cpp
        include/crypto/Jwt.hpp
        src/Encoding.cpp
        include/crypto/Encoding.hpp
        include/crypto.hpp)


target_link_libraries(qtGG-crypto nlohmann_json::nlohmann_json)
target_link_libraries(qtGG-crypto OpenSSL::SSL OpenSSL::Crypto)
