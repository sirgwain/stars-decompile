# toolchain-mingw64.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 10)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_AR        x86_64-w64-mingw32-ar)
set(CMAKE_RANLIB    x86_64-w64-mingw32-ranlib)
set(CMAKE_NM        x86_64-w64-mingw32-nm)
set(CMAKE_STRIP     x86_64-w64-mingw32-strip)

# Avoid macOS-only flags like -arch arm64 getting added
set(CMAKE_OSX_ARCHITECTURES "" CACHE STRING "")

# Make try-compile a static lib so it doesn't try to link an exe with host tooling
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# (Optional) help CMake find headers/libs from the MinGW sysroot
# adjust the path if your Homebrew prefix differs
set(CMAKE_FIND_ROOT_PATH "/opt/homebrew/opt/mingw-w64")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
