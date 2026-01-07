cmake_minimum_required(VERSION 3.20)
project(stars_decompile C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(STARS_BUILD_CLI   "Build portable CLI executable (main.c)" ON)
option(STARS_BUILD_WIN32 "Build Win32 GUI executable (winmain.c)" OFF)

# --- Core library: all .c in root, excluding entrypoints ---
file(GLOB STARSRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/*.c")

# Remove entrypoints from the core library so we don't get duplicate symbols.
list(REMOVE_ITEM STARSRCS
  "${CMAKE_SOURCE_DIR}/main.c"
  "${CMAKE_SOURCE_DIR}/winmain.c"
)

add_library(stars_core STATIC ${STARSRCS})
target_include_directories(stars_core PUBLIC ${CMAKE_SOURCE_DIR})

# Warnings
if (MSVC)
  target_compile_options(stars_core PRIVATE /W3)
else()
  target_compile_options(stars_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# --- CLI executable (main.c) ---
if (STARS_BUILD_CLI)
  add_executable(stars_cli "${CMAKE_SOURCE_DIR}/main.c")
  target_link_libraries(stars_cli PRIVATE stars_core)
  target_compile_definitions(stars_cli PRIVATE STARS_CLI=1)
endif()

# --- Win32 GUI executable (winmain.c) ---
if (STARS_BUILD_WIN32)
  if (WIN32)
    add_executable(stars_win32 WIN32 "${CMAKE_SOURCE_DIR}/winmain.c")
    target_link_libraries(stars_win32 PRIVATE stars_core)
    target_compile_definitions(stars_win32 PRIVATE STARS_WIN32=1)

    # Add these when you start calling real Win32 APIs:
    # target_link_libraries(stars_win32 PRIVATE user32 gdi32 comdlg32 shell32)
  else()
    message(FATAL_ERROR "STARS_BUILD_WIN32 is ON but this is not a Windows build.")
  endif()
endif()
