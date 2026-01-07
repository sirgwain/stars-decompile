cmake_minimum_required(VERSION 3.20)
project(stars_decompile C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(STARS_BUILD_CLI   "Build portable CLI executable (main.c)" ON)
option(STARS_BUILD_WIN32 "Build Win32 GUI executable (winmain.c)" OFF)

# CrossOver helpers: useful when *host* is macOS even if *target* is Windows
option(CROSSOVER_ENABLE "Enable CrossOver copy/run helpers (macOS host)" ON)

# -------- Host vs Target --------
set(HOST_IS_MAC OFF)
if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  set(HOST_IS_MAC ON)
endif()

message(STATUS "Host=${CMAKE_HOST_SYSTEM_NAME} Target=${CMAKE_SYSTEM_NAME} WIN32=${WIN32}")
message(STATUS "STARS_BUILD_CLI=${STARS_BUILD_CLI} STARS_BUILD_WIN32=${STARS_BUILD_WIN32}")
message(STATUS "CROSSOVER_ENABLE=${CROSSOVER_ENABLE} HOST_IS_MAC=${HOST_IS_MAC}")

# -------- Sources: flat directory --------
file(GLOB STARSRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/*.c")

# Do not compile entrypoints into the core library.
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

# -------- CLI executable: main() --------
if (STARS_BUILD_CLI)
  add_executable(stars_cli "${CMAKE_SOURCE_DIR}/main.c")
  target_link_libraries(stars_cli PRIVATE stars_core)
  target_compile_definitions(stars_cli PRIVATE STARS_CLI=1)
endif()

# -------- Win32 GUI executable: WinMain() --------
# Note: This is "target Windows" (WIN32=TRUE). On macOS you can still build this
# by using a Windows toolchain (e.g. mingw-w64) and setting CMAKE_SYSTEM_NAME=Windows.
if (STARS_BUILD_WIN32)
  if (WIN32)
    add_executable(stars_win32 WIN32 "${CMAKE_SOURCE_DIR}/winmain.c")
    target_link_libraries(stars_win32 PRIVATE stars_core)
    target_compile_definitions(stars_win32 PRIVATE STARS_WIN32=1)

    # Add Win32 libs when you start using them:
    # target_link_libraries(stars_win32 PRIVATE user32 gdi32 comdlg32 comctl32 shell32)
  else()
    message(FATAL_ERROR "STARS_BUILD_WIN32=ON requires targeting Windows (WIN32=TRUE). Use a Windows toolchain.")
  endif()
endif()

# ---------- CrossOver convenience targets (macOS host) ----------
# These are intentionally gated on HOST (macOS), not TARGET.
# They copy/run the Windows build output (stars_win32.exe) in a bottle.
set(CROSSOVER_BOTTLE_DIR
  "$ENV{HOME}/Library/Application Support/CrossOver/Bottles/debugger/drive_c/stars"
  CACHE PATH "Destination folder inside the bottle C: drive")

set(CROSSOVER_BIN
  "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin"
  CACHE PATH "CrossOver bin dir (may contain wine)")

set(CROSSOVER_APP_NAME "CrossOver" CACHE STRING "Application name for /usr/bin/open -a")
set(CROSSOVER_BOTTLE_NAME "debugger" CACHE STRING "Bottle name to use (for wine --bottle)")

# Keep the filename in the bottle stable
set(CROSSOVER_EXE "stars_win32.exe" CACHE STRING "Executable filename to copy/run inside bottle")

if (CROSSOVER_ENABLE AND HOST_IS_MAC)

  add_custom_target(copy_to_crossover
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CROSSOVER_BOTTLE_DIR}"
    COMMENT "Copying ${CROSSOVER_EXE} to CrossOver bottle: ${CROSSOVER_BOTTLE_DIR}"
  )

  if (TARGET stars_win32)
    add_dependencies(copy_to_crossover stars_win32)
    add_custom_command(TARGET copy_to_crossover POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "$<TARGET_FILE:stars_win32>"
              "${CROSSOVER_BOTTLE_DIR}/${CROSSOVER_EXE}"
      VERBATIM
    )
  else()
    add_custom_command(TARGET copy_to_crossover POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
              "Note: build the 'stars_win32' target first (STARS_BUILD_WIN32=ON, targeting Windows), then re-run 'copy_to_crossover'."
      VERBATIM
    )
  endif()

  set(WINE_BIN "${CROSSOVER_BIN}/wine")
  if (EXISTS "${WINE_BIN}")
    add_custom_target(run_in_crossover
      COMMAND "${WINE_BIN}" --bottle "${CROSSOVER_BOTTLE_NAME}" "c:\\\\stars\\\\${CROSSOVER_EXE}"
      DEPENDS copy_to_crossover
      COMMENT "Launching ${CROSSOVER_EXE} inside CrossOver bottle '${CROSSOVER_BOTTLE_NAME}'"
    )
  else()
    add_custom_target(run_in_crossover
      COMMAND /usr/bin/open -a "${CROSSOVER_APP_NAME}"
      COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
              "In CrossOver → Bottles → ${CROSSOVER_BOTTLE_NAME} → Run Command… choose C:\\\\stars\\\\${CROSSOVER_EXE}"
      DEPENDS copy_to_crossover
      COMMENT "Opening CrossOver; follow GUI to run the app"
    )
  endif()

else()
  add_custom_target(copy_to_crossover
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "CrossOver helpers available only on macOS host with CROSSOVER_ENABLE=ON."
    COMMENT "CrossOver copy helper unavailable"
  )
  add_custom_target(run_in_crossover
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow
            "CrossOver helpers available only on macOS host with CROSSOVER_ENABLE=ON."
    COMMENT "CrossOver run helper unavailable"
  )
endif()
