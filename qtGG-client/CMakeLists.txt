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

add_executable(qtGG-client main.cpp
        ListWindow/ListWindow.cpp
        ListWindow/ListWindow.hpp
        ../qtGG-accmgr/LoginWindow.cpp
        ../qtGG-accmgr/LoginWindow.hpp)
target_link_libraries(qtGG-client
  Qt::Core
  Qt::Gui
  Qt::Widgets
)

