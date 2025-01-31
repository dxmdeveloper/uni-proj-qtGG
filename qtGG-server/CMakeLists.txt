cmake_minimum_required(VERSION 3.30)
project(qtGG-server)

set(CMAKE_CXX_STANDARD 20)

find_package(Crow)
find_package(OpenSSL)
find_package(Qt6 COMPONENTS Sql Core REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/qtGG-crypto/include)

add_executable(qtGG-server main.cpp
        config.hpp
        Auth/Auth.hpp
        Auth/Auth.cpp
        common.hpp
        Auth/Routes.cpp
        Auth/Routes.hpp
        Conversations/Conversation.cpp
        Conversations/Conversation.hpp
        Conversations/KeyExchange.cpp
        Conversations/KeyExchange.hpp
        Conversations/Messages.cpp
        Conversations/Messages.hpp
        Conversations/Routes.cpp
        Conversations/Routes.hpp
        Users/Users.cpp
        Users/Users.hpp
        Users/Routes.cpp
        Users/Routes.hpp)

# Link the libqtGG-crypto.a library and its dependencies
target_link_libraries(qtGG-server PUBLIC Crow::Crow)
target_link_libraries(qtGG-server PRIVATE Qt6::Sql Qt6::Core)
target_link_libraries(qtGG-server PRIVATE qtGG-crypto)
target_link_libraries(qtGG-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)