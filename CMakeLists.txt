cmake_minimum_required(VERSION 3.5)
project(express.hpp)

set(CMAKE_CXX_STANDARD 17)

add_executable(cxxrest test.cpp express.hpp)
