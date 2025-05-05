# HPKV FUSE Filesystem (`hpkvfs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`hpkvfs` is a filesystem driver implemented using FUSE (Filesystem in Userspace) that allows you to mount a [HPKV (High-Performance Key-Value) Store](https://hpkv.io/) bucket as a standard filesystem. It interacts with the HPKV REST API to perform filesystem operations, translating file and directory actions into key-value operations.

This enables accessing and manipulating data stored in HPKV using standard command-line tools (`ls`, `cp`, `mv`, `rm`, `mkdir`, `cat`, `echo`, etc.) and applications, providing a familiar interface to a powerful key-value storage backend.

**Current Status:** Implemented file chunking to support files larger than the HPKV API's 3KB value limit. File operations (read, write, create, delete) appear functional based on user testing. Fixed an issue in `readdir` that caused `ls` to fail with an "Input/output error" by preventing empty entry names from being added. Packaged for Debian/Ubuntu (`.deb`). Further testing is recommended.

## Platform Support

*   **Linux (Primary & Tested):** Developed and tested primarily on Linux (Ubuntu). Requires `libfuse`. `.deb` package available for Ubuntu 22.04 (Jammy) and derivatives.
*   **macOS (Experimental):** Includes experimental support for macOS. Requires [macFUSE](https://osxfuse.github.io/) (the successor to FUSE for macOS). Build and runtime behavior are **experimental and not guaranteed**.
*   **Windows (Unsupported):** Windows is **not currently supported**. The FUSE API is not native to Windows. Porting this project would require significant effort to use a compatibility layer like [Dokan](https://dokan-dev.github.io/) or [WinFsp](https://winfsp.dev/).

## Features

*   **Mount HPKV as Filesystem:** Access your HPKV data through a standard directory structure (Linux, experimental macOS).
*   **REST API Integration:** Communicates directly with the HPKV REST API.
*   **API Key Authentication:** Securely authenticates using your HPKV API key via the `x-api-key` header.
*   **File Chunking:** Splits files larger than ~3KB into multiple chunks stored as separate keys (`<path>.chunkN`) to overcome API value size limits.
*   **Standard Filesystem Operations:** Supports core operations including:
    *   `getattr` (Get file/directory attributes)
    *   `readdir` (List directory contents - *Fixed I/O error*)
    *   `mkdir` (Create directories)
    *   `rmdir` (Remove empty directories - *Note: Emptiness check currently not implemented*)
    *   `create` (Create new empty files)
    *   `open` (Open files, handles `O_TRUNC`)
    *   `read` (Read file content, handles chunking)
    *   `write` (Write file content, handles chunking)
    *   `truncate` (Change file size, handles chunking)
    *   `unlink` (Delete files, handles chunking)
    *   `rename` (Rename/move files and directories, handles chunking - *Note: Not atomic*)
    *   `chmod` (Change permissions)
    *   `chown` (Change owner/group - *requires appropriate system permissions, limited on macOS/Windows*)
    *   `utimens` (Change access/modification times)
*   **Metadata Storage:** Stores filesystem metadata (mode, size, timestamps, owner, chunk info) alongside content in HPKV using dedicated keys (`<path>.__meta__`).
*   **Error Handling:** Maps HPKV API errors to standard POSIX filesystem errors.
*   **Retry Logic:** Implements basic retry logic with exponential backoff for transient API errors (e.g., rate limits, server errors).
*   **CMake Build System:** Uses CMake for cross-platform building (Linux, experimental macOS).
*   **Build Script:** Includes a simple `build.sh` script for convenience on Unix-like systems.
*   **Debian Packaging:** Includes configuration for building `.deb` packages for Debian/Ubuntu.

## Dependencies

**Runtime Dependencies (for using the installed package or binary):**
*   `fuse`: The FUSE runtime library and utilities.
*   `libcurl4`: The cURL library for HTTP requests.
*   `libjansson4`: The Jansson library for JSON parsing.

**Build Dependencies (for building from source):**

**Common:**
1.  **`cmake`:** Cross-platform build system generator (>= 3.10).
2.  **`pkg-config`:** Helper tool to get compiler/linker flags.
3.  **`libcurl4-openssl-dev`** (or similar): Development files for the cURL library.
4.  **`libjansson-dev`:** Development files for the Jansson library.
5.  **A C Compiler:** Such as `gcc` or `clang`.
6.  **Build Tools:** `make` or `ninja-build`.

**Platform-Specific:**
*   **Linux:** `libfuse-dev` (or `fuse-devel` on some distributions).
*   **macOS (Experimental):** [macFUSE](https://osxfuse.github.io/) (install the SDK and runtime). Dependencies like `curl` and `jansson` are typically installed via [Homebrew](https://brew.sh/) (`brew install curl jansson pkg-config cmake`).

**Debian/Ubuntu Build Environment Setup:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config fuse libfuse-dev libcurl4-openssl-dev libjansson-dev debhelper devscripts dh-make
```

## Installation (Debian/Ubuntu)

**Using the `.deb` Package:**

If you have the `hpkvfs_*.deb` package file:

1.  **Install the package:**
    ```bash
    sudo dpkg -i hpkvfs_*.deb
    ```
2.  **Fix Dependencies (if necessary):** If `dpkg` reports missing dependencies, run:
    ```bash
    sudo apt-get install -f
    ```
    This will automatically install `fuse`, `libcurl4`, and `libjansson4` if they are not already present.

**Using an APT Repository (Recommended - Requires Setup):**

For easier installation and updates, it's recommended to host the `.deb` package in a Personal Package Archive (PPA) on Launchpad or create your own custom APT repository.

*(Instructions for adding and using a specific PPA or repository would go here once available.)*

## Building from Source

This project uses CMake. You can use the provided build script or follow the manual CMake steps.

**Using the Build Script (Recommended on Linux/macOS):**

1.  **Ensure Dependencies:** Make sure all **Build Dependencies** listed above are installed.
2.  **Run the Script:** Execute the `build.sh` script from the project's root directory.
    ```bash
    ./build.sh
    ```
    This will create a `build` directory, run CMake, and run `make`. The resulting `hpkvfs` executable will be in the `build` directory.

**Manual CMake Steps:**

1.  **Create a build directory:**
    ```bash
    mkdir build
    cd build
    ```
2.  **Configure using CMake:**
    ```bash
    cmake .. 
    ```
3.  **Compile:**
    ```bash
    make 
    ```
    The `hpkvfs` executable will be in the `build` directory.

**Building the `.deb` Package (Debian/Ubuntu):**

1.  **Ensure Dependencies:** Install all **Build Dependencies** including the Debian packaging tools (`debhelper`, `devscripts`, `dh-make`).
2.  **Build the Package:** From the project's root directory, run:
    ```bash
    dpkg-buildpackage -us -uc
    ```
    This will create the `hpkvfs_*.deb` package in the parent directory (`../`).

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
3.  **Initialize Root (Important!):** Before the first mount, ensure the root metadata exists in HPKV. Use `curl` or another tool to create the key `/.__meta__` with a value like:
    ```json
    {"mode": 16877, "uid": 1000, "gid": 1000, "size": 0, "atime": 1714902307, "mtime": 1714902307, "ctime": 1714902307}
    ```
    (Replace UID/GID/timestamps as needed. The value must be a JSON *string* when using the API directly).
4.  **Mount:** Run `hpkvfs` with the mount point, API key, and API URL.
    ```bash
    # If installed via .deb package:
hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    # If built from source:
    ./build/hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    ```
5.  **Unmount:**
    *   Foreground (`-f`): Press `Ctrl+C`.
    *   Background: `fusermount -u ~/my_hpkv_drive`

**macOS (Experimental):**
*(Usage similar to Linux, but requires building from source and using macFUSE)*

**Common FUSE Options:**
*   `-f`: Run in the foreground (useful for debugging).
*   `-s`: Run single-threaded (can help with debugging).
*   `-d`: Enable FUSE-level debug messages (very verbose).
*   `-o allow_other`: Allow other users access (requires `user_allow_other` in `/etc/fuse.conf` on Linux, or specific macFUSE settings).

**HPKVFS Options:**
*   `--api-key=<key>`: (Required) Your HPKV API key.
*   `--api-url=<url>`: (Required) The base URL of your HPKV REST API instance (e.g., `https://api-eu-1.hpkv.io`).

**Example:**
```bash
hpkvfs ~/my_hpkv_drive --api-key=d2e022c1d3b94b3180f5179da422d437 --api-url=https://api-eu-1.hpkv.io -f
```

## Design & Implementation

*   **Language:** C
*   **Build System:** CMake
*   **Core Libraries:** `libfuse` (Linux) / `macFUSE` (macOS), `libcurl`, `jansson`.
*   **Key Mapping:**
    *   Metadata (mode, size, uid, gid, atime, mtime, ctime, num_chunks, chunk_size) for `/path/to/object` is stored as a JSON string under the key `/path/to/object.__meta__`.
    *   File content for `/path/to/file` is split into chunks (default ~3KB) and stored under keys like `/path/to/file.chunk0`, `/path/to/file.chunk1`, etc.
    *   Directories do not have content keys; their existence is defined by their metadata key.
*   **API Interaction:** All filesystem operations are mapped to HPKV REST API calls (`GET`, `POST`, `DELETE`).

For more detailed information on the design choices and implementation strategy for each FUSE operation, please refer to the `hpkvfs_design.md` document included in this repository.

## Limitations & Known Issues

*   **Experimental Platforms:** macOS support is experimental. Windows is unsupported.
*   **Atomicity:** The `rename` operation is not atomic. It involves copying data/metadata to the new location and then deleting the old location. An interruption during this process could lead to an inconsistent state.
*   **`rmdir` Emptiness Check:** The current implementation of `rmdir` does not check if a directory is empty before attempting deletion via the API. This might lead to unexpected behavior or errors if the directory is not empty.
*   **Performance:** Performance is directly tied to the latency and throughput of the HPKV REST API. Operations involving multiple API calls (like `write`, `truncate`, `rename`, `readdir`, especially with chunking) may be significantly slower than local filesystem operations.
*   **Binary Data:** While efforts were made to handle binary data using `json_stringn` and size information from metadata, thorough testing across various binary file types is recommended, especially regarding JSON encoding/decoding within chunks.
*   **Error Handling:** While basic error mapping and retries are implemented, complex failure scenarios or specific HPKV error conditions might require more sophisticated handling, especially during multi-chunk operations.
*   **Concurrency:** No explicit locking is implemented. Concurrent operations from multiple clients or processes might lead to race conditions or inconsistent states, particularly when modifying the same file's chunks or metadata.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

*   **kakooch**

## Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/kakooch/hpkvfs).



