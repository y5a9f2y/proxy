cmake_minimum_required(VERSION 3.0.2)

project(proxy)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

file(GLOB_RECURSE PROXY_CORE src/*)
list(REMOVE_ITEM PROXY_CORE ${PROJECT_SOURCE_DIR}/src/proxy_main.cc)

include_directories(${PROJECT_SOURCE_DIR}/src)
add_library(proxy_core STATIC ${PROXY_CORE})
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS
filesystem
system
)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Can not found boost")
else()
    message(STATUS "Boost library is founded")
    message(STATUS "The include directory of boost is ${Boost_INCLUDE_DIRS}")
    message(STATUS "The library directory of boost if ${Boost_LIBRARIES}")
    include_directories(${Boost_INCLUDE_DIRS})
endif()

add_library(libglog STATIC IMPORTED)
set_target_properties(libglog PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libglog.a")

add_library(libcoroutine STATIC IMPORTED)
set_target_properties(libcoroutine PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libcoroutine.a")

add_library(libssl STATIC IMPORTED)
set_target_properties(libssl PROPERTIES IMPORTED_LOCATION "/usr/local/lib64/libssl.a")

add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION "/usr/local/lib64/libcrypto.a")

include_directories("/usr/local/include")

# cmake -D DEBUG_mode=ON ..
if(DEBUG_mode)
    message(STATUS "build the debug version and linking the unit tests")
    add_definitions(-DDEBUG)
    set(CMAKE_CXX_FLAGS "-O0 -DDEBUG -g -ggdb -Wall -std=c++11")
else()
    message(STATUS "build the release version")
    add_definitions(-DNDEBUG)
    set(CMAKE_CXX_FLAGS "-O2 -Wall -g -ggdb -std=c++11")
    add_executable(proxy ${PROJECT_SOURCE_DIR}/src/proxy_main.cc)
    target_link_libraries(proxy proxy_core ${Boost_LIBRARIES} libglog libcoroutine 
       libssl libcrypto pthread dl resolv)
endif()
