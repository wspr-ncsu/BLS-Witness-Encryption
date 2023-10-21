CMAKE_MINIMUM_REQUIRED(VERSION 3.14.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release"
    CACHE STRING "Possible values are empty, Debug, Release, RelWithDebInfo, MinSizeRel, ..."
    FORCE
  )
endif()

project(witenc VERSION 0.1.0 LANGUAGES C CXX)

set(BUILD_WITENC_TESTS "1" CACHE STRING "")
set(BUILD_WITENC_BENCHMARKS "1" CACHE STRING "")

message(STATUS "Build tests: ${BUILD_WITENC_TESTS}")
message(STATUS "Build benchmarks: ${BUILD_WITENC_BENCHMARKS}")

include(FetchContent)

set(BLS_GIT_TAG "origin/main")
set(BLS_REPOSITORY "https://github.com/kofi-dalvik/bls-signatures.git")

message(STATUS "bls will be built from: ${BLS_GIT_TAG} and repository ${BLS_REPOSITORY}")

FetchContent_Declare(
  bls
  GIT_REPOSITORY ${BLS_REPOSITORY}
  GIT_TAG ${BLS_GIT_TAG}
)
FetchContent_MakeAvailable(bls)

add_subdirectory(src)