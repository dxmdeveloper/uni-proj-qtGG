cmake_minimum_required(VERSION 3.30)
project(qtGG-accmgr)

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
find_package(nlohmann_json REQUIRED)

add_library(qtGG-accmgr SHARED
        src/LoginWindow.cpp
        src/LoginWindow.hpp
        src/main.cpp
        src/RegistrationDialog.cpp
        src/RegistrationDialog.hpp
        src/internal_common.hpp
        src/Client.cpp
        src/Client.hpp
        include/accmgr.h)

include_directories(include)

set_target_properties(qtGG-accmgr PROPERTIES PUBLIC_HEADER include/accmgr.h)

target_link_libraries(qtGG-accmgr nlohmann_json::nlohmann_json)
target_link_libraries(qtGG-accmgr
        Qt::Core
        Qt::Gui
        Qt::Widgets
        Qt::Network
)
