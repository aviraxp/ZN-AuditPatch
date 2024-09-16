cmake_minimum_required(VERSION 3.22.1)
project(auditpatch)

set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

add_library(${MODULE_NAME} SHARED hook.cpp)
target_link_libraries(${MODULE_NAME} log)
