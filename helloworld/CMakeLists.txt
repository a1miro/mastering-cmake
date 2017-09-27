cmake_minimum_required (VERSION 2.6)
project (hello)

set (SOURCE src/helloworld.cpp)
set (VTK_USE_HYBRID ON)
set (CMAKE_CXX_FLAGS "-std=c++11 -g")

add_executable (hello ${SOURCE})

target_link_libraries(hello crypto)