
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.10.0
)
FetchContent_MakeAvailable(pybind11)

pybind11_add_module(witencpy ${CMAKE_CURRENT_SOURCE_DIR}/witencpy.cpp)
target_link_libraries(witencpy PRIVATE witenc)

if((NOT MSVC) AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_options(witencpy PRIVATE -Wl,-Bsymbolic)
endif()
