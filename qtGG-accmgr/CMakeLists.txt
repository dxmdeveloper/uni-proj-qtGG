#TODO: turn into dynamic library
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


add_executable(qtGG-accmgr LoginWindow.cpp LoginWindow.hpp
        main.cpp
        RegistrationDialog.cpp
        RegistrationDialog.hpp
        internal_common.hpp
        Client.cpp
        Client.hpp
        exports.h)

target_link_libraries(qtGG-accmgr nlohmann_json::nlohmann_json)
target_link_libraries(qtGG-accmgr
        Qt::Core
        Qt::Gui
        Qt::Widgets
        Qt::Network
)

