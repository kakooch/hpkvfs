# HPKV FUSE Filesystem (`hpkvfs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`hpkvfs` is a filesystem driver implemented using FUSE (Filesystem in Userspace) that allows you to mount a [HPKV (High-Performance Key-Value) Store](https://hpkv.io/) bucket as a standard filesystem. It interacts with the HPKV REST API to perform filesystem operations, translating file and directory actions into key-value operations.

This enables accessing and manipulating data stored in HPKV using standard command-line tools (`ls`, `cp`, `mv`, `rm`, `mkdir`, `cat`, `echo`, etc.) and applications, providing a familiar interface to a powerful key-value storage backend.

## Platform Support

*   **Linux (Primary & Tested):** Developed and tested primarily on Linux (Ubuntu). Requires `libfuse`.
*   **macOS (Experimental):** Includes experimental support for macOS. Requires [macFUSE](https://osxfuse.github.io/) (the successor to FUSE for macOS). Build and runtime behavior are **experimental and not guaranteed**.
*   **Windows (Unsupported):** Windows is **not currently supported**. The FUSE API is not native to Windows. Porting this project would require significant effort to use a compatibility layer like [Dokan](https://dokan-dev.github.io/) or [WinFsp](https://winfsp.dev/).

## Features

*   **Mount HPKV as Filesystem:** Access your HPKV data through a standard directory structure (Linux, experimental macOS).
*   **REST API Integration:** Communicates directly with the HPKV REST API.
*   **API Key Authentication:** Securely authenticates using your HPKV API key via the `x-api-key` header.
*   **Standard Filesystem Operations:** Supports core operations including:
    *   `getattr` (Get file/directory attributes)
    *   `readdir` (List directory contents)
    *   `mkdir` (Create directories)
    *   `rmdir` (Remove empty directories - *Note: Emptiness check currently not implemented*)
    *   `create` (Create new empty files)
    *   `open` (Open files)
    *   `read` (Read file content)
    *   `write` (Write file content - *overwrites/extends*)
    *   `truncate` (Change file size)
    *   `unlink` (Delete files)
    *   `rename` (Rename/move files and directories - *Note: Not atomic*)
    *   `chmod` (Change permissions)
    *   `chown` (Change owner/group - *requires appropriate system permissions, limited on macOS/Windows*)
    *   `utimens` (Change access/modification times)
*   **Metadata Storage:** Stores filesystem metadata (mode, size, timestamps, owner) alongside content in HPKV using dedicated keys.
*   **Error Handling:** Maps HPKV API errors to standard POSIX filesystem errors.
*   **Retry Logic:** Implements basic retry logic with exponential backoff for transient API errors (e.g., rate limits, server errors).
*   **CMake Build System:** Uses CMake for cross-platform building (Linux, experimental macOS).
*   **Build Script:** Includes a simple `build.sh` script for convenience on Unix-like systems.

## Dependencies

To build and run `hpkvfs`, you need the following development packages:

**Common:**
1.  **`cmake`:** Cross-platform build system generator (>= 3.10).
2.  **`pkg-config`:** Helper tool to get compiler/linker flags.
3.  **`libcurl`:** Development files for the cURL library (used for HTTP requests).
4.  **`jansson`:** Development files for the Jansson library (used for JSON parsing).
5.  **A C Compiler:** Such as `gcc` or `clang`.
6.  **Build Tools:** `make` or `ninja-build`.

**Platform-Specific:**
*   **Linux:** `libfuse-dev` (or `fuse-devel` on some distributions), `fuse` runtime package.
*   **macOS (Experimental):** [macFUSE](https://osxfuse.github.io/) (install the SDK and runtime). Dependencies like `curl` and `jansson` are typically installed via [Homebrew](https://brew.sh/) (`brew install curl jansson pkg-config cmake`).

**Installation Examples:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install -y cmake pkg-config fuse libfuse-dev libcurl4-openssl-dev libjansson-dev build-essential
    ```
*   **macOS (using Homebrew):**
    1.  Install [macFUSE](https://osxfuse.github.io/) (download from website).
    2.  Install build tools and libraries:
        ```bash
        brew install cmake pkg-config curl jansson
        ```

## Building

This project uses CMake. You can use the provided build script or follow the manual CMake steps.

**Using the Build Script (Recommended on Linux/macOS):**

1.  **Ensure Dependencies:** Make sure all dependencies listed above are installed.
2.  **Run the Script:** Execute the `build.sh` script from the project's root directory.
    ```bash
    ./build.sh
    ```
    This will create a `build` directory, run CMake, and run `make`. The resulting `hpkvfs` executable will be in the `build` directory.

**Manual CMake Steps:**

1.  **Create a build directory:** It's best practice to build outside the source directory.
    ```bash
    mkdir build
    cd build
    ```

2.  **Configure using CMake:** Run CMake to configure the project and generate build files (e.g., Makefiles or Ninja files).
    ```bash
    # On Linux/macOS:
    cmake .. 
    
    # Optional: Specify installation prefix
    # cmake .. -DCMAKE_INSTALL_PREFIX=/path/to/install
    
    # Optional: Specify generator (e.g., for Ninja)
    # cmake .. -G Ninja
    ```
    CMake will detect the operating system and attempt to find the required dependencies (libfuse/macFUSE, libcurl, jansson).

3.  **Compile:** Run the build tool (e.g., `make` or `ninja`).
    ```bash
    make 
    # or
    # ninja
    ```
    This will create the `hpkvfs` executable in the `build` directory.

4.  **(Optional) Install:** To install the `hpkvfs` binary to the configured installation path (default: `/usr/local/bin` on Unix-like systems), run:
    ```bash
    sudo make install
    # or
    # sudo ninja install
    ```
    *Note: Installation is not configured for Windows.* 

## Usage

**Linux:**
1.  **Load FUSE Module (if needed):** Ensure the FUSE kernel module is loaded.
    ```bash
    sudo modprobe fuse
    ```
2.  **Create Mount Point:** Create an empty directory.
    ```bash
    mkdir ~/my_hpkv_drive
    ```
3.  **Mount:** Run `hpkvfs` with the mount point, API key, and API URL.
    ```bash
    # From build directory:
    ./build/hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    # If installed:
    hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    ```
4.  **Unmount:**
    *   Foreground (`-f`): Press `Ctrl+C`.
    *   Background: `fusermount -u ~/my_hpkv_drive`

**macOS (Experimental):**
1.  **Install macFUSE:** Ensure macFUSE is installed and kernel extension is allowed.
2.  **Create Mount Point:** `mkdir ~/my_hpkv_drive`
3.  **Mount:** Similar to Linux, using the compiled `hpkvfs` binary.
    ```bash
    ./build/hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    ```
    *Note: Standard FUSE options like `-o allow_other` might require specific macFUSE configuration.* 
4.  **Unmount:**
    *   Foreground (`-f`): Press `Ctrl+C`.
    *   Background: `umount ~/my_hpkv_drive` or `diskutil unmount ~/my_hpkv_drive`

**Common FUSE Options:**
*   `-f`: Run in the foreground (useful for debugging).
*   `-s`: Run single-threaded (can help with debugging).
*   `-o allow_other`: Allow other users access (requires `user_allow_other` in `/etc/fuse.conf` on Linux, or specific macFUSE settings).
*   `-o debug`: Enable FUSE-level debug messages.

**HPKVFS Options:**
*   `--api-key=<key>`: (Required) Your HPKV API key.
*   `--api-url=<url>`: (Required) The base URL of your HPKV REST API instance (e.g., `https://api-eu-1.hpkv.io`).

**Example:**
```bash
./build/hpkvfs ~/my_hpkv_drive --api-key=d2e022c1d3b94b3180f5179da422d437 --api-url=https://api-eu-1.hpkv.io -f
```

## Design & Implementation

*   **Language:** C
*   **Build System:** CMake
*   **Core Libraries:** `libfuse` (Linux) / `macFUSE` (macOS), `libcurl`, `jansson`.
*   **Key Mapping:**
    *   File content for `/path/to/file` is stored under the key `/path/to/file`.
    *   Metadata (mode, size, uid, gid, atime, mtime, ctime) for `/path/to/object` is stored as a JSON string under the key `/path/to/object.__meta__`.
    *   Directories do not have a content key; their existence is defined by their metadata key.
*   **API Interaction:** All filesystem operations are mapped to HPKV REST API calls (`GET`, `POST`, `DELETE`).

For more detailed information on the design choices and implementation strategy for each FUSE operation, please refer to the `hpkvfs_design.md` document included in this repository.

## Limitations & Known Issues

*   **Debugging Status:** The current version has known issues with mounting and basic operations (like `ls`) that are still under investigation. Use with caution.
*   **Experimental Platforms:** macOS support is experimental. Windows is unsupported.
*   **Atomicity:** The `rename` operation is not atomic. It involves copying data/metadata to the new location and then deleting the old location. An interruption during this process could lead to an inconsistent state.
*   **`rmdir` Emptiness Check:** The current implementation of `rmdir` does not check if a directory is empty before attempting deletion via the API. This might lead to unexpected behavior or errors if the directory is not empty.
*   **Performance:** Performance is directly tied to the latency and throughput of the HPKV REST API. Operations involving multiple API calls (like `write`, `truncate`, `rename`, `readdir`) may be significantly slower than local filesystem operations.
*   **Large Files:** The current `write` and `truncate` implementations read the entire file content into memory, modify it, and write it back. This is highly inefficient for large files.
*   **Binary Data:** While efforts were made to handle binary data using `json_stringn` and size information from metadata, thorough testing across various binary file types is recommended, especially regarding JSON encoding/decoding.
*   **Error Handling:** While basic error mapping and retries are implemented, complex failure scenarios or specific HPKV error conditions might require more sophisticated handling.
*   **Concurrency:** No explicit locking is implemented. Concurrent operations from multiple clients or processes might lead to race conditions or inconsistent states.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

*   **kakooch**

## Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/kakooch/hpkvfs).


