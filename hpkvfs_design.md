# HPKV FUSE Filesystem Design

This document outlines the design for a FUSE (Filesystem in Userspace) driver that uses the HPKV REST API as its storage backend.

## 1. Core Components & Language

*   **Language:** C
*   **FUSE Library:** `libfuse` (version 2 or 3, prefer 3 if available and compatible)
*   **HTTP Client:** `libcurl` for making REST API calls to HPKV.
*   **JSON Parsing:** `jansson` for parsing JSON responses from the HPKV API and potentially for storing metadata.

## 2. Dependencies

The build process will require the development packages for:

*   `fuse` / `libfuse-dev`
*   `libcurl` / `libcurl4-openssl-dev`
*   `jansson` / `libjansson-dev`
*   A C compiler (e.g., `gcc`)
*   `make` for building

## 3. Key Mapping Strategy

*   **Files:** The content of a file located at `/path/to/file` will be stored in the HPKV store using the absolute path `/path/to/file` as the key.
*   **Directories:** Directories themselves won't have a dedicated content key. Their existence will be implicitly defined by the presence of their metadata key.
*   **Metadata:** Filesystem metadata (permissions, size, timestamps - mtime, atime, ctime, type) for both files and directories will be stored in separate keys. For an object at `/path/to/object`, its metadata will be stored under the key `/path/to/object.__meta__`. The metadata value will be a JSON string containing the necessary attributes.
    *   Example Metadata JSON: `{"mode": 33188, "size": 1024, "uid": 1000, "gid": 1000, "atime": 1678886400, "mtime": 1678886400, "ctime": 1678886400}` (mode represents a regular file with 644 permissions).
*   **Root Directory:** The root directory `/` will have its metadata stored under the key `/.__meta__`.

## 4. FUSE Operation Implementation Strategy

All operations will interact with the HPKV REST API using `libcurl`.

*   **`getattr(path, statbuf)`:**
    1.  Construct the metadata key: `path + "__meta__"`.
    2.  Attempt `GET /record/:metakey`.
    3.  If successful (200 OK): Parse the JSON metadata value, populate `statbuf` (mode, size, uid, gid, times). Return 0.
    4.  If not found (404): Return `-ENOENT`.
    5.  Handle other errors (401, 403, 5xx) by returning appropriate FUSE errors (`-EACCES`, `-EIO`). Implement retries for 5xx/429 errors.
*   **`readdir(path, buf, filler, offset, fi)`:**
    1.  Ensure `path` ends with `/`.
    2.  Construct `startKey = path` and `endKey = path + "\xFF"` (or similar logic to get keys prefixed by `path`).
    3.  Perform `GET /records?startKey=...&endKey=...&limit=1000` (handle potential pagination if API supports/needs it, although the current doc shows max limit 1000).
    4.  Parse the response (list of records).
    5.  For each key in the result:
        *   Extract the component name immediately following `path`.
        *   Filter out deeper entries (e.g., if listing `/dir/`, ignore `/dir/subdir/file`).
        *   Remove the `.__meta__` suffix if present.
        *   Use `filler(buf, name, NULL, 0)` to add unique names to the listing.
    6.  Add `.` and `..` using `filler`.
    7.  Return 0 on success, or error code on API failure.
*   **`mkdir(path, mode)`:**
    1.  Construct the metadata key: `path + "/.__meta__"`.
    2.  Create a JSON metadata object representing a directory with the given `mode` and current timestamps.
    3.  Perform `POST /record` with `key = metakey` and `value = json_metadata`.
    4.  Return 0 on success (2xx), `-EEXIST` if key already exists (API might return specific code?), or other error codes.
*   **`rmdir(path)`:**
    1.  Ensure `path` ends with `/`.
    2.  Perform `readdir` logic to check if the directory is empty (contains only `.` and `..`). If not empty, return `-ENOTEMPTY`.
    3.  Construct metadata key: `path + "__meta__"`.
    4.  Perform `DELETE /record/:metakey`.
    5.  Return 0 on success, `-ENOENT` if not found, or other error codes.
*   **`create(path, mode, fi)`:**
    1.  Construct metadata key `path + "__meta__"` and content key `path`.
    2.  Create JSON metadata for a new file (mode, size 0, uid, gid, current times).
    3.  Perform `POST /record` for the metadata key.
    4.  Perform `POST /record` for the content key with an empty string value.
    5.  Handle potential race conditions/errors (e.g., file already exists). Return 0 on success.
*   **`open(path, fi)`:**
    1.  Construct metadata key `path + "__meta__"`.
    2.  Perform `GET /record/:metakey` to check existence and retrieve metadata.
    3.  If not found, return `-ENOENT`.
    4.  Check permissions based on `fi->flags` against the retrieved metadata mode. Return `-EACCES` if insufficient.
    5.  (Optional: Store file handle info in `fi->fh` if needed for optimization, though maybe not necessary for simple stateless operations).
    6.  Return 0.
*   **`read(path, buf, size, offset, fi)`:**
    1.  Perform `GET /record/:path` to retrieve the file content.
    2.  If not found, return `-ENOENT`.
    3.  If successful, copy `size` bytes starting from `offset` from the retrieved value into `buf`. Handle boundary conditions (offset > length, offset + size > length).
    4.  Return the number of bytes read.
    5.  (Optional: Update `atime` in metadata - requires GET meta, update, POST meta).
*   **`write(path, buf, size, offset, fi)`:**
    1.  Perform `GET /record/:path` to retrieve the current content.
    2.  Modify the content in memory: Create a new buffer, copy content before `offset`, copy `size` bytes from `buf`, copy content after `offset + size` (if overwriting). Handle extending the file.
    3.  Perform `POST /record` with the *entire* new content.
    4.  Update metadata: Get `path + "__meta__"`, update size, mtime, ctime, then `POST` the updated metadata.
    5.  Return `size` (number of bytes written).
*   **`truncate(path, size)`:**
    1.  Perform `GET /record/:path`.
    2.  If `size` is less than current length, truncate the content in memory. If `size` is greater, pad with null bytes.
    3.  Perform `POST /record` with the new content.
    4.  Update metadata (size, mtime, ctime) via GET/POST on `path + "__meta__"`.
    5.  Return 0.
*   **`unlink(path)`:**
    1.  Perform `DELETE /record/:path`.
    2.  Perform `DELETE /record/:path.__meta__`.
    3.  Return 0 on success (ignore 404 for one if the other succeeded, maybe?).
*   **`rename(from_path, to_path)`:**
    1.  Get content from `from_path`.
    2.  Get metadata from `from_path.__meta__`.
    3.  `POST` content to `to_path`.
    4.  `POST` metadata to `to_path.__meta__`.
    5.  `DELETE` `from_path`.
    6.  `DELETE` `from_path.__meta__`.
    7.  This is NOT atomic. If any step fails, the filesystem could be left in an inconsistent state. Add checks (e.g., if `to_path` exists). Handle directory renames carefully (check if `to_path` exists and is an empty dir if `from_path` is a dir).
*   **`setattr(path, statbuf, to_set)`:**
    1.  Get current metadata from `path.__meta__`.
    2.  Update fields indicated by `to_set` (e.g., mode, uid, gid, size (via truncate), atime, mtime).
    3.  `POST` the updated metadata back to `path.__meta__`.
    4.  Return 0.

## 5. Authentication & Configuration

*   The FUSE driver will accept the HPKV API Base URL and API Key as command-line arguments (e.g., using `fuse_opt_parse`).
*   The API key will be stored securely in memory and sent in the `x-api-key` header with every API request.

## 6. Error Handling

*   Map HPKV HTTP status codes (400, 401, 403, 404, 409, 429, 500) to appropriate POSIX/FUSE error codes (`EINVAL`, `EACCES`, `EACCES`, `ENOENT`, `EEXIST`?, `EBUSY`?, `EIO`).
*   Implement a retry mechanism (e.g., exponential backoff) for transient errors like 429 (Too Many Requests) and 5xx (Server Error) as requested by the user.

## 7. Build Process

*   A `Makefile` will be provided to compile the C source code (`hpkvfs.c`) into an executable binary (`hpkvfs`).
*   Compilation command example:
    `gcc hpkvfs.c -o hpkvfs $(pkg-config --cflags --libs fuse libcurl-openssl jansson)`

## 8. Future Considerations (Post-MVP)

*   **Caching:** Implement local caching (metadata and/or data blocks) for performance.
*   **Atomicity:** Investigate if HPKV offers any transaction or batch operations to improve atomicity for operations like `rename`.
*   **Write Performance:** Explore alternative write strategies if the read-modify-write approach proves too slow, although the API seems limited here.
*   **Concurrency:** Ensure thread-safety if `libfuse` is used in multi-threaded mode (use thread-safe `libcurl` and `jansson` functions, protect shared state).

