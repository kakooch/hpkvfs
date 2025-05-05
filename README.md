# HPKV FUSE Filesystem (`hpkvfs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`hpkvfs` is a filesystem driver implemented using FUSE (Filesystem in Userspace) that allows you to mount a [HPKV (High-Performance Key-Value) Store](https://hpkv.io/) bucket as a standard filesystem on Linux systems. It interacts with the HPKV REST API to perform filesystem operations, translating file and directory actions into key-value operations.

This enables accessing and manipulating data stored in HPKV using standard command-line tools (`ls`, `cp`, `mv`, `rm`, `mkdir`, `cat`, `echo`, etc.) and applications, providing a familiar interface to a powerful key-value storage backend.

## Features

*   **Mount HPKV as Filesystem:** Access your HPKV data through a standard directory structure.
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
    *   `chown` (Change owner/group - *requires appropriate system permissions*)
    *   `utimens` (Change access/modification times)
*   **Metadata Storage:** Stores filesystem metadata (mode, size, timestamps, owner) alongside content in HPKV using dedicated keys.
*   **Error Handling:** Maps HPKV API errors to standard POSIX filesystem errors.
*   **Retry Logic:** Implements basic retry logic with exponential backoff for transient API errors (e.g., rate limits, server errors).
*   **CMake Build System:** Uses CMake for robust building and installation.

## Dependencies

To build and run `hpkvfs`, you need the following development packages:

1.  **`cmake`:** Cross-platform build system generator.
2.  **`pkg-config`:** Helper tool to get compiler/linker flags.
3.  **`libfuse-dev`:** Development files for FUSE (Filesystem in Userspace).
4.  **`libcurl4-openssl-dev` (or similar):** Development files for the cURL library (used for HTTP requests).
5.  **`libjansson-dev`:** Development files for the Jansson library (used for JSON parsing).
6.  **A C Compiler:** Such as `gcc` or `clang`.
7.  **`make` or `ninja-build`:** A build tool that CMake can generate files for.

On **Debian/Ubuntu-based systems**, you can install these using:

```bash
sudo apt-get update
sudo apt-get install -y cmake pkg-config fuse libfuse-dev libcurl4-openssl-dev libjansson-dev build-essential
```
*Note: `build-essential` typically includes `gcc` and `make`.*

## Building

This project uses CMake. The standard build process is as follows:

1.  **Create a build directory:** It's best practice to build outside the source directory.
    ```bash
    mkdir build
    cd build
    ```

2.  **Configure using CMake:** Run CMake to configure the project and generate build files (e.g., Makefiles).
    ```bash
    cmake ..
    ```
    *   You can specify an installation prefix here if desired: `cmake .. -DCMAKE_INSTALL_PREFIX=/path/to/install`

3.  **Compile:** Run the build tool (usually `make`).
    ```bash
    make
    ```
    This will create the `hpkvfs` executable in the `build` directory.

4.  **(Optional) Install:** To install the `hpkvfs` binary to the configured installation path (default: `/usr/local/bin`), run:
    ```bash
    sudo make install
    ```

## Usage

1.  **Load FUSE Module (if needed):** Ensure the FUSE kernel module is loaded.
    ```bash
    sudo modprobe fuse
    ```

2.  **Create Mount Point:** Create an empty directory where you want to mount the HPKV filesystem.
    ```bash
    mkdir ~/my_hpkv_drive
    ```

3.  **Mount the Filesystem:** Run the `hpkvfs` executable (either from the build directory or the installed location), providing the mount point, your HPKV API key, and the HPKV REST API base URL.
    ```bash
    # If running from build directory:
    ./hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    
    # If installed:
    hpkvfs ~/my_hpkv_drive --api-key=<YOUR_HPKV_API_KEY> --api-url=<YOUR_HPKV_API_URL> [FUSE options]
    ```
    *   Replace `<YOUR_HPKV_API_KEY>` with your actual API key.
    *   Replace `<YOUR_HPKV_API_URL>` with the base URL for your HPKV instance (e.g., `https://api-eu-1.hpkv.io`).
    *   **Common FUSE options:**
        *   `-f`: Run in the foreground (useful for debugging). Without this, it runs as a background daemon.
        *   `-s`: Run single-threaded (can help with debugging).
        *   `-o allow_other`: Allow other users (besides the one mounting) to access the filesystem (requires `user_allow_other` in `/etc/fuse.conf`).

    **Example:**
    ```bash
    ./hpkvfs ~/my_hpkv_drive --api-key=d2e022c1d3b94b3180f5179da422d437 --api-url=https://api-eu-1.hpkv.io -f
    ```

4.  **Access Files:** Once mounted, you can interact with the filesystem at `~/my_hpkv_drive` using standard tools.

5.  **Unmount:** To unmount the filesystem:
    *   If running in the foreground (`-f`), press `Ctrl+C` in the terminal where it's running.
    *   If running in the background, use `fusermount`:
        ```bash
        fusermount -u ~/my_hpkv_drive
        ```

## Design & Implementation

*   **Language:** C
*   **Build System:** CMake
*   **Core Libraries:** `libfuse` (v2.6+), `libcurl`, `jansson`.
*   **Key Mapping:**
    *   File content for `/path/to/file` is stored under the key `/path/to/file`.
    *   Metadata (mode, size, uid, gid, atime, mtime, ctime) for `/path/to/object` is stored as a JSON string under the key `/path/to/object.__meta__`.
    *   Directories do not have a content key; their existence is defined by their metadata key.
*   **API Interaction:** All filesystem operations are mapped to HPKV REST API calls (`GET`, `POST`, `DELETE`).

For more detailed information on the design choices and implementation strategy for each FUSE operation, please refer to the `hpkvfs_design.md` document included in this repository.

## Limitations

*   **Atomicity:** The `rename` operation is not atomic. It involves copying data/metadata to the new location and then deleting the old location. An interruption during this process could lead to an inconsistent state.
*   **`rmdir` Emptiness Check:** The current implementation of `rmdir` does not check if a directory is empty before attempting deletion via the API. This might lead to unexpected behavior if the underlying API allows deleting non-empty directories or if other clients modify the store concurrently.
*   **Performance:** Performance is directly tied to the latency and throughput of the HPKV REST API. Operations involving multiple API calls (like `write`, `truncate`, `rename`) may be slower than local filesystem operations.
*   **Binary Data:** While efforts were made to handle binary data using `json_stringn` and size information from metadata, thorough testing across various binary file types is recommended.
*   **Error Handling:** While basic error mapping and retries are implemented, complex failure scenarios or specific HPKV error conditions might require more sophisticated handling.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Author

*   **kakooch**

## Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/kakooch/hpkvfs).

