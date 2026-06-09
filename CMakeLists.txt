cmake_minimum_required(VERSION 3.16)
project(AES_Lab1 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Release build by default ──────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ─── Find Crypto++ ─────────────────────────────────────────────
# Try CMake config first, then fall back to manual search
find_package(cryptopp CONFIG QUIET)

if(NOT cryptopp_FOUND)
  # Manual fallback — common install locations
  find_library(CRYPTOPP_LIB
    NAMES cryptopp libcryptopp
    PATHS
      /usr/lib /usr/local/lib
      /usr/lib/x86_64-linux-gnu
      "C:/cryptopp/lib"
      "C:/vcpkg/installed/x64-windows/lib"
  )
  find_path(CRYPTOPP_INCLUDE
    NAMES cryptlib.h
    PATHS
      /usr/include/cryptopp
      /usr/local/include/cryptopp
      "C:/cryptopp/include"
      "C:/vcpkg/installed/x64-windows/include"
  )
  if(NOT CRYPTOPP_LIB OR NOT CRYPTOPP_INCLUDE)
    message(FATAL_ERROR
      "Crypto++ not found.\n"
      "  Linux : sudo apt install libcryptopp-dev\n"
      "  Windows: vcpkg install cryptopp:x64-windows\n")
  endif()
  add_library(cryptopp::cryptopp UNKNOWN IMPORTED)
  set_target_properties(cryptopp::cryptopp PROPERTIES
    IMPORTED_LOCATION "${CRYPTOPP_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE}")
endif()

# ─── aescli ────────────────────────────────────────────────────
add_executable(aescli aescli.cpp)
target_link_libraries(aescli PRIVATE cryptopp::cryptopp)

if(MSVC)
  target_compile_options(aescli PRIVATE /W3 /O2)
else()
  target_compile_options(aescli PRIVATE -Wall -O2)
endif()

# ─── bench ─────────────────────────────────────────────────────
add_executable(bench bench.cpp)
target_link_libraries(bench PRIVATE cryptopp::cryptopp)

if(MSVC)
  target_compile_options(bench PRIVATE /W3 /O2)
else()
  target_compile_options(bench PRIVATE -Wall -O3 -march=native)
endif()

# ─── Install ───────────────────────────────────────────────────
install(TARGETS aescli bench DESTINATION bin)

# ─── Summary ───────────────────────────────────────────────────
message(STATUS "Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Targets     : aescli, bench")
