# CMakeLists.txt for HPKV FUSE Filesystem

cmake_minimum_required(VERSION 3.10)

project(hpkvfs VERSION 0.1.0 LANGUAGES C)

# Find required packages using pkg-config
find_package(PkgConfig REQUIRED)

pkg_check_modules(FUSE REQUIRED fuse)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)

# Add required FUSE definition
add_definitions(-D_FILE_OFFSET_BITS=64)

# Include directories from found packages
include_directories(${FUSE_INCLUDE_DIRS})
include_directories(${LIBCURL_INCLUDE_DIRS})
include_directories(${JANSSON_INCLUDE_DIRS})

# Add compiler warnings
add_compile_options(-Wall -Wextra)

# Define the executable target
add_executable(hpkvfs hpkvfs.c)

# Link libraries
target_link_libraries(hpkvfs
    PRIVATE
    ${FUSE_LIBRARIES}
    ${LIBCURL_LIBRARIES}
    ${JANSSON_LIBRARIES}
)

# Installation target (install to /usr/local/bin by default)
include(GNUInstallDirs)
install(TARGETS hpkvfs
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

message(STATUS "Configured HPKV FUSE Filesystem (hpkvfs)")
message(STATUS "  FUSE include dirs: ${FUSE_INCLUDE_DIRS}")
message(STATUS "  FUSE libraries: ${FUSE_LIBRARIES}")
message(STATUS "  Libcurl include dirs: ${LIBCURL_INCLUDE_DIRS}")
message(STATUS "  Libcurl libraries: ${LIBCURL_LIBRARIES}")
message(STATUS "  Jansson include dirs: ${JANSSON_INCLUDE_DIRS}")
message(STATUS "  Jansson libraries: ${JANSSON_LIBRARIES}")
message(STATUS "Install target: ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")

