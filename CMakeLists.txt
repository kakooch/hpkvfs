# CMakeLists.txt for HPKV FUSE Filesystem (Cross-Platform Attempt)

cmake_minimum_required(VERSION 3.10)

project(hpkvfs VERSION 0.1.1 LANGUAGES C)

# --- Options --- 
# option(ENABLE_MACOS_EXPERIMENTAL "Enable experimental macOS build (requires macFUSE)" OFF)
# option(ENABLE_WINDOWS_EXPERIMENTAL "Enable experimental Windows build (requires Dokan/WinFSP port)" OFF)

# --- System Detection --- 
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(TARGET_LINUX TRUE)
    message(STATUS "Detected System: Linux")
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(TARGET_MACOS TRUE)
    message(STATUS "Detected System: macOS (Experimental Support)")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(TARGET_WINDOWS TRUE)
    message(STATUS "Detected System: Windows (Experimental - Requires Porting)")
else()
    message(FATAL_ERROR "Unsupported operating system: ${CMAKE_SYSTEM_NAME}")
endif()

# --- Find Dependencies --- 
find_package(PkgConfig REQUIRED)

# Common dependencies
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)

# FUSE dependency (Linux/macOS)
if(TARGET_LINUX OR TARGET_MACOS)
    # On macOS, pkg-config should find macFUSE if installed via Homebrew
    pkg_check_modules(FUSE REQUIRED fuse)
    if(NOT FUSE_FOUND)
        message(FATAL_ERROR "FUSE library not found. Please install libfuse-dev (Linux) or macFUSE (macOS).")
    endif()
    # Add required FUSE definition
    add_definitions(-D_FILE_OFFSET_BITS=64)
    include_directories(${FUSE_INCLUDE_DIRS})
    list(APPEND HPKVFS_LINK_LIBRARIES ${FUSE_LIBRARIES})
else()
    # Placeholder for Windows dependencies (Dokan/WinFsp)
    message(WARNING "Windows build requires porting to Dokan or WinFsp. FUSE dependency skipped.")
endif()

# --- Compiler Flags --- 
# Add common warnings
add_compile_options(-Wall -Wextra)

# Add OS-specific flags if needed
if(TARGET_MACOS)
    # Potentially add macOS specific flags, e.g., target version
    # add_compile_options(-mmacosx-version-min=10.13)
endif()

# --- Target Definition --- 
add_executable(hpkvfs hpkvfs.c)

# --- Linking --- 
# Add common libraries
include_directories(${LIBCURL_INCLUDE_DIRS})
include_directories(${JANSSON_INCLUDE_DIRS})
list(APPEND HPKVFS_LINK_LIBRARIES ${LIBCURL_LIBRARIES})
list(APPEND HPKVFS_LINK_LIBRARIES ${JANSSON_LIBRARIES})

# Link all collected libraries
target_link_libraries(hpkvfs PRIVATE ${HPKVFS_LINK_LIBRARIES})

# --- Installation --- 
if(NOT TARGET_WINDOWS)
    # Standard installation for Unix-like systems
    include(GNUInstallDirs)
    install(TARGETS hpkvfs
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    message(STATUS "Install target configured: ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
else()
    # Define Windows installation if needed (e.g., copy to a program files dir)
    message(STATUS "Install target skipped for Windows (requires specific setup).")
endif()

# --- Status Messages --- 
message(STATUS "Configured HPKV FUSE Filesystem (hpkvfs v${PROJECT_VERSION})")
message(STATUS "  Target OS: ${CMAKE_SYSTEM_NAME}")
if(FUSE_FOUND)
    message(STATUS "    FUSE include dirs: ${FUSE_INCLUDE_DIRS}")
    message(STATUS "    FUSE libraries: ${FUSE_LIBRARIES}")
endif()
message(STATUS "    Libcurl include dirs: ${LIBCURL_INCLUDE_DIRS}")
message(STATUS "    Libcurl libraries: ${LIBCURL_LIBRARIES}")
message(STATUS "    Jansson include dirs: ${JANSSON_INCLUDE_DIRS}")
message(STATUS "    Jansson libraries: ${JANSSON_LIBRARIES}")



