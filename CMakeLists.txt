cmake_minimum_required(VERSION 3.20)
project(qtGG)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(qtGG-accmgr)
add_subdirectory(qtGG-crypto)
add_subdirectory(qtGG-client)
add_subdirectory(qtGG-server)
