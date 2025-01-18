cmake_minimum_required(VERSION 3.30)
project(qtGG-client)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

# Add executable
add_executable(qtGG-client src/main.cpp
        src/ListWindow/ListWindow.cpp
        src/ListWindow/ListWindow.hpp
        ../qtGG-accmgr/src/LoginWindow.cpp
        ../qtGG-accmgr/src/LoginWindow.hpp)

# Link Qt libraries
target_link_libraries(qtGG-client
        Qt::Core
        Qt::Gui
        Qt::Widgets
)

# --- Handle qtGG-accmgr shared library ---
# Determine library file based on platform
if(WIN32)
    set(LIBRARY_NAME libqtGG-accmgr.dll)
else()
    set(LIBRARY_NAME libqtGG-accmgr.so)
endif()

set(CPY_SOURCE_LIBRARY_PATH "${CMAKE_BINARY_DIR}/qtGG-accmgr/${LIBRARY_NAME}")
set(CPY_DEST_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libs/${LIBRARY_NAME}")


# If the library exists, add a custom command to copy it if different
if(EXISTS "${CPY_SOURCE_LIBRARY_PATH}")
    message("library build directory found")

    add_custom_command(
            TARGET qtGG-client PRE_LINK
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CPY_SOURCE_LIBRARY_PATH}" "${CPY_DEST_LIBRARY_PATH}"
            COMMENT "Copying ${LIBRARY_NAME} to libs directory if it exists and is newer or missing"
    )
else ()
    message("library build directory not found")
endif ()

# Path to the library in the source tree
set(SOURCE_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libs/${LIBRARY_NAME}")
# Set RPATH on Linux to use $ORIGIN (the executable's directory)
if(UNIX)
    set_target_properties(qtGG-client PROPERTIES
            BUILD_RPATH "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
    )
endif()

# Link the library from the source directory (temporary)
target_link_libraries(qtGG-client "${SOURCE_LIBRARY_PATH}")

# Include directories for accmgr
include_directories(libs/include)
