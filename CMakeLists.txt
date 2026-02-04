cmake_minimum_required(VERSION 3.20)
project(stars_decompile C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directories (keeps build products predictable across generators)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

option(STARS_BUILD_CLI   "Build portable CLI executable (main.c)" ON)
option(STARS_BUILD_WIN32 "Build Win32 GUI executable (winmain.c)" OFF)
option(STARS_BUILD_TESTS "Build unit tests (acutest)" ON)

message(STATUS "Host=${CMAKE_HOST_SYSTEM_NAME} Target=${CMAKE_SYSTEM_NAME} WIN32=${WIN32}")
message(STATUS "STARS_BUILD_CLI=${STARS_BUILD_CLI} STARS_BUILD_WIN32=${STARS_BUILD_WIN32} STARS_BUILD_TESTS=${STARS_BUILD_TESTS}")

# -------- Sources --------
file(GLOB STARSRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/*.c")

# Do not compile entrypoints into the core library.
list(REMOVE_ITEM STARSRCS
  "${CMAKE_SOURCE_DIR}/main.c"
  "${CMAKE_SOURCE_DIR}/winmain.c"
)

add_library(stars_core STATIC)
target_sources(stars_core PRIVATE ${STARSRCS})
target_include_directories(stars_core PUBLIC "${CMAKE_SOURCE_DIR}")

# Debug logging is compiled in for Debug builds.
target_compile_definitions(stars_core PUBLIC $<$<CONFIG:Debug>:STARS_DEBUG=1>)

# Warnings
target_compile_options(stars_core PRIVATE
  $<$<C_COMPILER_ID:MSVC>:/W3>
  $<$<NOT:$<C_COMPILER_ID:MSVC>>:-Wall -Wextra -Wno-unused-parameter -Werror=incompatible-pointer-types>
)

# Math library (sqrt, etc.) - let it propagate to users of stars_core.
if (NOT MSVC)
  target_link_libraries(stars_core PUBLIC m)
endif()

# -------- Unit tests (acutest) --------
if (STARS_BUILD_TESTS)
  enable_testing()

  # Build one test executable per test_*.c file.
  file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/test/test_*.c")

  set(TEST_TARGETS "")
  foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

    add_executable(${TEST_NAME})
    target_sources(${TEST_NAME} PRIVATE ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE stars_core)

    target_include_directories(${TEST_NAME} PRIVATE
      "${CMAKE_SOURCE_DIR}"
      "${CMAKE_SOURCE_DIR}/test"
    )

    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    set_tests_properties(${TEST_NAME} PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")

    list(APPEND TEST_TARGETS ${TEST_NAME})
  endforeach()

  # Convenience target: build + run all tests
  add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${TEST_TARGETS}
    COMMENT "Running all tests"
  )
endif()

# -------- CLI executable: main() --------
if (STARS_BUILD_CLI)
  add_executable(stars_cli "${CMAKE_SOURCE_DIR}/main.c")
  target_link_libraries(stars_cli PRIVATE stars_core)
  target_compile_definitions(stars_cli PRIVATE STARS_CLI=1)
endif()

# -------- Win32 GUI executable: WinMain() --------
# This is "target Windows" (WIN32=TRUE). On macOS/Linux you can still build this
# by using a Windows toolchain (e.g. mingw-w64) and setting CMAKE_SYSTEM_NAME=Windows.
if (STARS_BUILD_WIN32)
  if (WIN32)
    add_executable(stars_win32 WIN32
      "${CMAKE_SOURCE_DIR}/winmain.c"
      "${CMAKE_SOURCE_DIR}/res/stars.rc"
    )
    target_link_libraries(stars_win32 PRIVATE stars_core)
    target_compile_definitions(stars_win32 PRIVATE STARS_WIN32=1)

    target_include_directories(stars_win32 PRIVATE
      "${CMAKE_SOURCE_DIR}"
      "${CMAKE_SOURCE_DIR}/res"
    )

    # Add Win32 libs when you start using them:
    # target_link_libraries(stars_win32 PRIVATE user32 gdi32 comdlg32 comctl32 shell32)
  else()
    message(FATAL_ERROR "STARS_BUILD_WIN32=ON requires targeting Windows (WIN32=TRUE). Use a Windows toolchain.")
  endif()
endif()

# -------- Wine convenience targets --------
# These are host-side launch helpers for the Windows target.
find_program(WINE_EXE wine)
if (WINE_EXE AND TARGET stars_win32)
  add_custom_target(run_in_wine
    COMMAND "${WINE_EXE}" "$<TARGET_FILE:stars_win32>"
    DEPENDS stars_win32
    COMMENT "Launching stars_win32 under wine"
  )

  add_custom_target(run_in_wine_gdb
    COMMAND "${WINE_EXE}" winedbg --gdb --no-start --port 1234 "$<TARGET_FILE:stars_win32>"
    DEPENDS stars_win32
    COMMENT "Launching stars_win32 under winedbg --gdb (port 1234)"
  )
elseif(TARGET stars_win32)
  add_custom_target(run_in_wine
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "wine not found in PATH."
    COMMENT "Wine run helper unavailable"
  )
  add_custom_target(run_in_wine_gdb
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "wine not found in PATH."
    COMMENT "Wine gdb run helper unavailable"
  )
else()
  add_custom_target(run_in_wine
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "Build the 'stars_win32' target first (STARS_BUILD_WIN32=ON, targeting Windows)."
    COMMENT "Wine run helper unavailable"
  )
  add_custom_target(run_in_wine_gdb
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "Build the 'stars_win32' target first (STARS_BUILD_WIN32=ON, targeting Windows)."
    COMMENT "Wine gdb run helper unavailable"
  )
endif()
