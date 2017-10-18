cmake_minimum_required (VERSION 2.6)
project (hello)

set (SOURCE src/helloworld.cpp)
set (VTK_USE_HYBRID ON)
set (CMAKE_CXX_FLAGS "-std=c++11 -g")

add_executable (hello ${SOURCE})

target_link_libraries(hello crypto)
#option(USE_JPEG "Do you want to use JPEG")

set(USE_JPEG ON CACHE BOOL "Enable JPEG support?")

set(CRYPTOBACKEND "OpenSSL" CACHE STRING "Select crypto backend")
set_property(CACHE CRYPTOBACKEND PROPERTY STRINGS "OpenSSL" "LibTomCrypt" "LibDES")
  