#!/bin/bash
# Simple build script for hpkvfs

set -e # Exit immediately if a command exits with a non-zero status.

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "Creating build directory: ${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "Changing to build directory..."
cd "${BUILD_DIR}"

echo "Running CMake..."
cmake ..

echo "Running make..."
make

echo "Build complete. Executable is at ${BUILD_DIR}/hpkvfs"

