file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

list(APPEND witenc_sources
  ${HEADERS}
  witenc.cpp
)

add_compile_options(-fno-builtin)
add_compile_options(-fPIC)
add_compile_options(-Wall)
add_compile_options(-Wextra)

if((CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)") AND (NOT EMSCRIPTEN))
  add_compile_options(-mno-avx)
endif()

add_library(witenc ${witenc_sources})

target_include_directories(witenc PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${bls_SOURCE_DIR}
)

target_link_libraries(witenc PUBLIC bls)

if(BUILD_WITENC_BENCHMARKS)
  add_executable(webench bench.cpp)
  target_link_libraries(webench PRIVATE witenc)
endif()

if(BUILD_WITENC_TESTS)
  add_executable(wetest test.cpp)
  target_link_libraries(wetest PRIVATE witenc)
endif()
