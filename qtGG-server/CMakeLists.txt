cmake_minimum_required(VERSION 3.30)
project(qtGG-server)

set(CMAKE_CXX_STANDARD 20)

find_package(Crow)
find_package(OpenSSL)
find_package(Qt6 COMPONENTS Sql Core REQUIRED)

add_executable(qtGG-server main.cpp
        config.hpp
        Auth/Auth.hpp
        Auth/Auth.cpp
        Auth/Auth.cpp
        Auth/Auth.cpp
        common.hpp
        Crypt/Crypt.cpp
        Crypt/Crypt.hpp
        Auth/Routes.cpp
        Auth/Routes.hpp
        Conversations/Conversation.cpp
        Conversations/Conversation.hpp
        Conversations/KeyExchange.cpp
        Conversations/KeyExchange.hpp
        Conversations/Messages.cpp
        Conversations/Messages.hpp
        Conversations/Routes.cpp
        Conversations/Routes.hpp)
target_link_libraries(qtGG-server PUBLIC Crow::Crow)
target_link_libraries(qtGG-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(qtGG-server PRIVATE Qt6::Sql Qt6::Core)
