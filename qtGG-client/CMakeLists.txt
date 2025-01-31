cmake_minimum_required(VERSION 3.20)
project(qtGG-client)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        Network
        REQUIRED)

find_package(OpenSSL)

include_directories(${CMAKE_SOURCE_DIR}/qtGG-crypto/include)
include_directories(${CMAKE_SOURCE_DIR}/qtGG-accmgr/include)

# Add executable
add_executable(qtGG-client src/main.cpp
        src/ListWindow/ListWindow.cpp
        src/ListWindow/ListWindow.hpp
        src/common.hpp
        src/ChatWindow/ChatWindow.cpp
        src/ChatWindow/ChatWindow.hpp)

# Link Qt libraries
target_link_libraries(qtGG-client
        Qt::Core
        Qt::Gui
        Qt::Widgets
        Qt::Network
)

# Link the libqtGG-crypto.a static library
target_link_libraries(qtGG-client qtGG-crypto)

# Link OpenSSL
target_link_libraries(qtGG-client OpenSSL::SSL OpenSSL::Crypto)

# --- Handle qtGG-accmgr shared library ---
if(WIN32)
    set(ACCMGR_BIN_FILE qtGG-accmgr.dll)
else()
    set(ACCMGR_BIN_FILE libqtGG-accmgr.so)
endif()

if(UNIX)
    add_custom_command(TARGET qtGG-client POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/qtGG-accmgr/${ACCMGR_BIN_FILE}
            $<TARGET_FILE_DIR:qtGG-client>
    )
endif ()

if(UNIX)
    set_target_properties(qtGG-client PROPERTIES
            BUILD_RPATH "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
    )
endif()
target_link_libraries(qtGG-client qtGG-accmgr)

