/*******************************************************************************
 * HPKV FUSE Filesystem
 * 
 * Connects to an HPKV REST API to provide a filesystem interface.
 * Supports Linux (primary) and experimental macOS (macFUSE).
 * Windows support requires significant porting (Dokan/WinFsp).
 * 
 * Implements file chunking to handle API value size limits.
 ******************************************************************************/

// Define FUSE version before including fuse.h
#define FUSE_USE_VERSION 26

// Platform-specific includes and definitions
#ifdef __linux__
    // Linux specific includes (if any)
    #include <unistd.h> // for usleep, getuid, getgid
#elif __APPLE__
    // macOS specific includes
    #include <unistd.h> // for usleep, getuid, getgid (usually available)
    // Potentially include macFUSE specific headers if needed later
#elif _WIN32
    // Windows specific includes (Placeholder - requires Dokan/WinFsp)
    #error "Windows is not supported in this FUSE-based implementation. Porting to Dokan or WinFsp is required."
    // #include <windows.h> 
    // Need alternative for usleep, getuid, getgid
#else
    #error "Unsupported operating system"
#endif

#include <fuse.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <stddef.h> // Needed for offsetof
#include <math.h>   // For ceil

// --- Debug Logging --- 
// Simple debug flag, could be made a command-line option later
#define HPKVFS_DEBUG 1

#ifdef HPKVFS_DEBUG
#define DEBUG_LOG(...) fprintf(stderr, "DEBUG: " __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

// --- Chunking Configuration ---
#define HPKV_CHUNK_SIZE 3000 // Max size per chunk (slightly less than 3072 limit)

// --- Configuration & State ---

typedef struct {
    char *api_base_url;
    char *api_key;
} hpkv_config;

// Get private data from FUSE context
#define HPKV_DATA ((hpkv_config *) fuse_get_context()->private_data)

// Structure to hold command line options (parsed by FUSE)
struct hpkv_options {
    const char *api_base_url;
    const char *api_key;
};

// --- Forward Declarations for FUSE Operations ---
static int hpkv_getattr(const char *path, struct stat *stbuf);
static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int hpkv_mkdir(const char *path, mode_t mode);
static int hpkv_rmdir(const char *path);
static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi);
static int hpkv_open(const char *path, struct fuse_file_info *fi);
static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int hpkv_truncate(const char *path, off_t size);
static int hpkv_unlink(const char *path);
static int hpkv_rename(const char *from, const char *to);
static int hpkv_chmod(const char *path, mode_t mode);
static int hpkv_chown(const char *path, uid_t uid, gid_t gid);
static int hpkv_utimens(const char *path, const struct timespec ts[2]);

// --- HTTP Request Helper ---

// Structure to hold response data from libcurl
struct MemoryStruct {
  char *memory;
  size_t size;
};

// Callback function for libcurl to write received data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    fprintf(stderr, "Error: not enough memory (realloc returned NULL)\n");
    return 0; // Returning 0 signals error to libcurl
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0; // Null-terminate the buffer
 
  return realsize;
}

// Helper to URL-encode a string
// Returns a newly allocated string that must be freed by the caller.
static char *url_encode(const char *input) {
    CURL *curl = curl_easy_init();
    char *output = NULL;
    if(curl) {
        output = curl_easy_escape(curl, input, 0); // 0 length means strlen
        curl_easy_cleanup(curl);
    }
    if (!output) {
        fprintf(stderr, "Error: Failed to url_encode string: %s\n", input);
        // Return an empty string allocated on heap to avoid NULL issues, caller still must free.
        output = strdup(""); 
        if (!output) {
             fprintf(stderr, "Error: strdup failed in url_encode fallback\n");
             // Extremely unlikely, but handle allocation failure
             return NULL; 
        }
    }
    return output;
}

// Function to perform HTTP requests to HPKV API
// Returns HTTP status code, or -1 on internal curl error.
// Populates response_chunk if successful (HTTP 2xx) and response_chunk is not NULL.
// Caller must free response_chunk->memory if it's not NULL.
static long perform_hpkv_request(
    const char *method, 
    const char *path_segment, // Should be already URL encoded if necessary
    const char *request_body, // For POST/PUT
    const char *request_body_n, // For POST/PUT with specific length (binary safe)
    size_t request_body_len, // Length for request_body_n
    struct MemoryStruct *response_chunk
) {
    CURL *curl_handle;
    CURLcode res;
    long http_code = 0;
    char full_url[2048]; // Increased buffer size
    struct curl_slist *headers = NULL;
    char api_key_header[256];

    DEBUG_LOG("perform_hpkv_request: Method=%s, PathSegment=%s\n", method, path_segment);

    // Initialize response chunk
    response_chunk->memory = malloc(1); 
    response_chunk->size = 0;    
    if (!response_chunk->memory) { 
        fprintf(stderr, "Error: malloc failed for response chunk\n"); 
        return -1; // Internal error
    }
    response_chunk->memory[0] = '\0';

    curl_handle = curl_easy_init();
    if (!curl_handle) {
        fprintf(stderr, "Error: Failed to initialize curl\n");
        free(response_chunk->memory);
        response_chunk->memory = NULL; // Ensure caller doesn't free invalid pointer
        return -1; // Internal error
    }

    // Construct full URL
    snprintf(full_url, sizeof(full_url), "%s%s", HPKV_DATA->api_base_url, path_segment);
    DEBUG_LOG("perform_hpkv_request: Full URL=%s\n", full_url);

    // Set common options
    curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response_chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "hpkvfs/0.1.2"); // Version bump
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connection timeout
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 60L);      // 60 seconds total timeout (increased for potentially larger ops)
    // Consider adding CURLOPT_FOLLOWLOCATION, 1L if redirects are expected/needed

    // Set headers
    snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", HPKV_DATA->api_key);
    headers = curl_slist_append(headers, api_key_header);
    if (request_body || request_body_n) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (request_body_n) {
             DEBUG_LOG("perform_hpkv_request: Request Body (len %zu)=%.100s%s\n", 
                       request_body_len, request_body_n, request_body_len > 100 ? "..." : "");
             curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, request_body_len);
             curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, request_body_n);
        } else {
             DEBUG_LOG("perform_hpkv_request: Request Body=%s\n", request_body);
             curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, request_body);
        }
    }
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

    // Set HTTP method
    if (strcmp(method, "GET") == 0) {
        // Default is GET
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    // Add PUT/PATCH if needed later

    // Perform the request
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_perform() failed: %s\nURL: %s\n", curl_easy_strerror(res), full_url);
        http_code = -1; // Indicate curl error
    } else {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
        DEBUG_LOG("perform_hpkv_request: HTTP Status Code=%ld\n", http_code);
        if (response_chunk->size > 0) {
             DEBUG_LOG("perform_hpkv_request: Response Body (first 100 bytes)=%.100s%s\n", 
                       response_chunk->memory, response_chunk->size > 100 ? "..." : "");
        }
    }

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);

    // If request failed internally or HTTP status indicates error, free response memory
    // as the content is likely error message or irrelevant.
    if (http_code < 200 || http_code >= 300) {
        if (response_chunk->memory) {
            free(response_chunk->memory);
            response_chunk->memory = NULL;
            response_chunk->size = 0;
        }
    }

    return http_code;
}

// Function to perform HTTP requests with retries for specific error codes.
static long perform_hpkv_request_with_retry(
    const char *method, 
    const char *path_segment, 
    const char *request_body, // For standard string body
    const char *request_body_n, // For length-specified body
    size_t request_body_len, // Length for request_body_n
    struct MemoryStruct *response_chunk,
    int max_retries
) {
    long http_code = -1;
    int retries = 0;
    long delay_ms = 100; // Initial delay 100ms

    while (retries <= max_retries) {
        // Ensure response chunk is reset for each attempt if needed (perform_hpkv_request handles init)
        http_code = perform_hpkv_request(method, path_segment, request_body, request_body_n, request_body_len, response_chunk);
        
        // Check if retry is needed (Rate limit, Server errors, or internal Curl error)
        if ((http_code == 429 || (http_code >= 500 && http_code < 600) || http_code == -1) && retries < max_retries) {
            fprintf(stderr, "Warning: Request failed with %ld, retrying (%d/%d) after %ld ms...\n", 
                    http_code, retries + 1, max_retries, delay_ms);
            #ifdef _WIN32
                // Sleep(delay_ms); // Windows Sleep function takes milliseconds
            #else
                usleep(delay_ms * 1000); // usleep takes microseconds
            #endif
            delay_ms *= 2; // Exponential backoff
            if (delay_ms > 5000) delay_ms = 5000; // Cap delay at 5 seconds
            retries++;
        } else {
            break; // No retry needed or max retries reached
        }
    }
    return http_code;
}

// Helper to map HTTP status codes to FUSE/POSIX error codes
static int map_http_to_fuse_error(long http_code) {
    switch (http_code) {
        case 200: case 201: case 204: return 0; // Success
        case 400: return -EINVAL; // Bad Request -> Invalid Argument
        case 401: return -EACCES; // Unauthorized -> Permission Denied
        case 403: return -EACCES; // Forbidden -> Permission Denied
        case 404: return -ENOENT; // Not Found -> No Such File or Directory
        case 409: return -EEXIST; // Conflict -> File Exists
        case 429: return -EBUSY;  // Too Many Requests -> Device or resource busy
        // Map common server errors to EIO (Input/output error)
        case 500: case 502: case 503: case 504: return -EIO;
        case -1:  return -EIO;    // Internal curl error -> Input/output error
        default:  return -EIO;    // Default to generic I/O error for unexpected codes
    }
}

// --- Metadata & Chunking Helpers ---

// Construct the metadata key for a given path.
static void get_meta_key(const char *path, char *meta_key_buf, size_t buf_size) {
    if (strcmp(path, "/") == 0) {
        snprintf(meta_key_buf, buf_size, "/.__meta__");
    } else {
        size_t path_len = strlen(path);
        if (path_len > 1 && path[path_len - 1] == '/') path_len--;
        snprintf(meta_key_buf, buf_size, "%.*s.__meta__", (int)path_len, path);
    }
}

// Construct the chunk key for a given base path and chunk index.
static void get_chunk_key(const char *base_path, int chunk_index, char *chunk_key_buf, size_t buf_size) {
    snprintf(chunk_key_buf, buf_size, "%s.chunk%d", base_path, chunk_index);
}

// Helper to get metadata JSON object for a path.
// Returns a new json_t object (caller must decref) or NULL on error/not found.
static json_t* get_metadata_json(const char *path) {
    DEBUG_LOG("get_metadata_json: Entered for path: %s\n", path);
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL, *inner_meta_json = NULL;
    json_error_t error;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: get_metadata_json(%s): Invalid FUSE context!\n", path);
        return NULL;
    }

    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("get_metadata_json: Meta key: %s\n", meta_key);
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: get_metadata_json(%s): URL encoding failed for meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return NULL;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("get_metadata_json: Performing GET request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: get_metadata_json(%s): Failed to parse outer JSON response: %s\n", path, error.text);
            return NULL;
        }
        value_json = json_object_get(root, "value");
        if (!json_is_string(value_json)) {
            fprintf(stderr, "Error: get_metadata_json(%s): API response missing 'value' string.\n", path);
            json_decref(root);
            return NULL;
        }
        const char *value_str = json_string_value(value_json);
        inner_meta_json = json_loads(value_str, 0, &error);
        if (!inner_meta_json) {
            fprintf(stderr, "Error: get_metadata_json(%s): Failed to parse inner JSON string from 'value': %s\n", path, error.text);
            json_decref(root);
            return NULL;
        }
        if (!json_is_object(inner_meta_json)) {
             fprintf(stderr, "Error: get_metadata_json(%s): Inner metadata is not a JSON object.\n", path);
             json_decref(inner_meta_json);
             json_decref(root);
             return NULL;
        }
        json_decref(root); // Decref outer object
        DEBUG_LOG("get_metadata_json(%s): Successfully parsed inner metadata JSON object.\n", path);
        return inner_meta_json; // Return the actual metadata object
    } else {
        if (response.memory) {
             free(response.memory);
             response.memory = NULL;
        }
        if (http_code != 404) {
             fprintf(stderr, "Warning: get_metadata_json: API GET failed for %s, HTTP: %ld\n", meta_key, http_code);
        }
        DEBUG_LOG("get_metadata_json: API GET failed or returned non-200 status (%ld). Returning NULL.\n", http_code);
        return NULL; // Not found or other API error
    }
}

// Helper to POST metadata JSON object for a path.
// Takes ownership of meta_json (will decref it).
// Returns 0 on success, or a negative FUSE error code on failure.
static int post_metadata_json(const char *path, json_t *meta_json) {
    DEBUG_LOG("post_metadata_json: Called for path: %s\n", path);
    char meta_key[1024];
    char *meta_json_str = NULL;
    char *request_body_str = NULL;
    json_t *request_body_json = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    if (!meta_json || !json_is_object(meta_json)) {
         fprintf(stderr, "Error: post_metadata_json: Invalid meta_json provided.\n");
         if (meta_json) json_decref(meta_json);
         return -EINVAL; 
    }

    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("post_metadata_json: Meta key: %s\n", meta_key);

    // Add/update chunking info if it's a file metadata
    if (json_object_get(meta_json, "mode") && S_ISREG(json_integer_value(json_object_get(meta_json, "mode")))) {
        json_object_set_new(meta_json, "chunk_size", json_integer(HPKV_CHUNK_SIZE));
        // num_chunks should be updated by write/truncate
        if (!json_object_get(meta_json, "num_chunks")) {
             json_object_set_new(meta_json, "num_chunks", json_integer(0)); // Default if missing
        }
    }

    meta_json_str = json_dumps(meta_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(meta_json); // Decref the original object
    if (!meta_json_str) {
        fprintf(stderr, "Error: post_metadata_json: Failed to dump inner metadata object to string for %s\n", meta_key);
        return -EIO;
    }
    DEBUG_LOG("post_metadata_json: Inner metadata string: %s\n", meta_json_str);

    request_body_json = json_object();
    if (!request_body_json) { free(meta_json_str); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(meta_key));
    json_object_set_new(request_body_json, "value", json_string(meta_json_str));
    free(meta_json_str);

    request_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    if (!request_body_str) {
        fprintf(stderr, "Error: post_metadata_json: Failed to dump full request JSON for %s\n", meta_key);
        return -EIO;
    }

    DEBUG_LOG("post_metadata_json: Performing POST request for %s\n", meta_key);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_body_str, NULL, 0, &response, 3);
    free(request_body_str);
    if (response.memory) {
         free(response.memory);
         response.memory = NULL;
    }

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Warning: post_metadata_json: Failed POST for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code, ret);
    }
    DEBUG_LOG("post_metadata_json: Finished for %s, returning %d\n", path, ret);
    return ret;
}

// Helper to GET a specific chunk of a file.
// Returns a malloc'd buffer with the chunk content (caller must free), or NULL on error/not found.
// Populates chunk_len with the length of the retrieved chunk data.
static char* get_chunk_content(const char *base_path, int chunk_index, size_t *chunk_len) {
    DEBUG_LOG("get_chunk_content: Called for path: %s, chunk: %d\n", base_path, chunk_index);
    char chunk_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL;
    json_error_t error;
    char *chunk_data = NULL;

    *chunk_len = 0;
    get_chunk_key(base_path, chunk_index, chunk_key, sizeof(chunk_key));
    DEBUG_LOG("get_chunk_content: Chunk key: %s\n", chunk_key);
    encoded_key = url_encode(chunk_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: get_chunk_content(%s, %d): URL encoding failed for chunk key.\n", base_path, chunk_index);
        if (encoded_key) free(encoded_key);
        return NULL;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("get_chunk_content: Performing GET request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: get_chunk_content(%s, %d): Failed to parse JSON response: %s\n", base_path, chunk_index, error.text);
            return NULL;
        }
        value_json = json_object_get(root, "value");
        if (!json_is_string(value_json)) {
            fprintf(stderr, "Error: get_chunk_content(%s, %d): API response 'value' is not a string.\n", base_path, chunk_index);
            json_decref(root);
            return NULL;
        }
        // Use json_string_length for binary safety
        *chunk_len = json_string_length(value_json);
        chunk_data = malloc(*chunk_len + 1); // +1 for potential null terminator
        if (!chunk_data) {
            fprintf(stderr, "Error: get_chunk_content(%s, %d): Failed to allocate memory for chunk data (%zu bytes).\n", base_path, chunk_index, *chunk_len);
            json_decref(root);
            return NULL;
        }
        memcpy(chunk_data, json_string_value(value_json), *chunk_len);
        chunk_data[*chunk_len] = '\0'; // Null-terminate
        json_decref(root);
        DEBUG_LOG("get_chunk_content(%s, %d): Successfully retrieved chunk, length %zu.\n", base_path, chunk_index, *chunk_len);
        return chunk_data;
    } else {
        if (response.memory) {
             free(response.memory);
             response.memory = NULL;
        }
        if (http_code != 404) {
            fprintf(stderr, "Warning: get_chunk_content: API GET failed for %s, HTTP: %ld\n", chunk_key, http_code);
        }
        DEBUG_LOG("get_chunk_content: Chunk %d not found or API error (%ld). Returning NULL.\n", chunk_index, http_code);
        return NULL; // Not found or other API error
    }
}

// Helper to POST a specific chunk of a file.
// Returns 0 on success, or a negative FUSE error code on failure.
static int post_chunk_content(const char *base_path, int chunk_index, const char *chunk_data, size_t chunk_len) {
    DEBUG_LOG("post_chunk_content: Called for path: %s, chunk: %d, len: %zu\n", base_path, chunk_index, chunk_len);
    char chunk_key[1024];
    char *request_body_str = NULL;
    json_t *request_body_json = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    if (chunk_len > HPKV_CHUNK_SIZE) {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): Attempted to write chunk larger than limit (%zu > %d)\n", 
                base_path, chunk_index, chunk_len, HPKV_CHUNK_SIZE);
        return -EINVAL;
    }

    get_chunk_key(base_path, chunk_index, chunk_key, sizeof(chunk_key));
    DEBUG_LOG("post_chunk_content: Chunk key: %s\n", chunk_key);

    request_body_json = json_object();
    if (!request_body_json) return -ENOMEM;
    json_object_set_new(request_body_json, "key", json_string(chunk_key));
    // Use json_stringn for binary safety
    json_object_set_new(request_body_json, "value", json_stringn(chunk_data, chunk_len));

    // Dump using json_dumps (handles escaping correctly)
    request_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    if (!request_body_str) {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): Failed to dump request JSON.\n", base_path, chunk_index);
        return -EIO;
    }

    DEBUG_LOG("post_chunk_content: Performing POST request for %s\n", chunk_key);
    // Use the version of perform_hpkv_request_with_retry that takes length
    http_code = perform_hpkv_request_with_retry("POST", "/record", NULL, request_body_str, strlen(request_body_str), &response, 3);
    free(request_body_str);
    if (response.memory) {
         free(response.memory);
         response.memory = NULL;
    }

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Warning: post_chunk_content: Failed POST for %s, HTTP: %ld, FUSE: %d\n", chunk_key, http_code, ret);
    }
    DEBUG_LOG("post_chunk_content: Finished for %s, chunk %d, returning %d\n", base_path, chunk_index, ret);
    return ret;
}

// Helper to DELETE a specific chunk of a file.
// Returns 0 on success or ENOENT, negative FUSE error code otherwise.
static int delete_chunk_content(const char *base_path, int chunk_index) {
    DEBUG_LOG("delete_chunk_content: Called for path: %s, chunk: %d\n", base_path, chunk_index);
    char chunk_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    get_chunk_key(base_path, chunk_index, chunk_key, sizeof(chunk_key));
    DEBUG_LOG("delete_chunk_content: Chunk key: %s\n", chunk_key);
    encoded_key = url_encode(chunk_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: delete_chunk_content(%s, %d): URL encoding failed.\n", base_path, chunk_index);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("delete_chunk_content: Performing DELETE request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, NULL, 0, &response, 3);
    if (response.memory) {
         free(response.memory);
         response.memory = NULL;
    }

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0 && ret != -ENOENT) {
        fprintf(stderr, "Warning: delete_chunk_content: Failed DELETE for %s, HTTP: %ld, FUSE: %d\n", chunk_key, http_code, ret);
    } else if (ret == -ENOENT) {
        DEBUG_LOG("delete_chunk_content: Chunk %s not found (ENOENT), considered success.\n", chunk_key);
        ret = 0; // Treat not found as success for deletion
    }
    DEBUG_LOG("delete_chunk_content: Finished for %s, chunk %d, returning %d\n", base_path, chunk_index, ret);
    return ret;
}


// --- FUSE Operations (Modified for Chunking) ---

// getattr: Get file attributes (mostly unchanged, reads size from metadata)
static int hpkv_getattr(const char *path, struct stat *stbuf) {
    DEBUG_LOG("hpkv_getattr: Entered for path: %s\n", path);
    json_t *meta_json = NULL, *j_val;
    int ret = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_getattr(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    memset(stbuf, 0, sizeof(struct stat));
    meta_json = get_metadata_json(path);

    if (meta_json) {
        DEBUG_LOG("hpkv_getattr(%s): get_metadata_json returned successfully. Populating stat buffer.\n", path);
        stbuf->st_mode = S_IFREG | 0644; 
        stbuf->st_nlink = 1;
        stbuf->st_size = 0;
        #ifdef _WIN32
            stbuf->st_uid = 0; stbuf->st_gid = 0;
        #else
            stbuf->st_uid = context->uid; stbuf->st_gid = context->gid;
        #endif
        time_t now = time(NULL);
        stbuf->st_atime = now; stbuf->st_mtime = now; stbuf->st_ctime = now;

        j_val = json_object_get(meta_json, "mode");
        if (json_is_integer(j_val)) stbuf->st_mode = (mode_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "size"); // Total logical size
        if (json_is_integer(j_val)) stbuf->st_size = (off_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "uid");
        if (json_is_integer(j_val)) stbuf->st_uid = (uid_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "gid");
        if (json_is_integer(j_val)) stbuf->st_gid = (gid_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "atime");
        if (json_is_integer(j_val)) stbuf->st_atime = (time_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "mtime");
        if (json_is_integer(j_val)) stbuf->st_mtime = (time_t)json_integer_value(j_val);
        j_val = json_object_get(meta_json, "ctime");
        if (json_is_integer(j_val)) stbuf->st_ctime = (time_t)json_integer_value(j_val);

        if (S_ISDIR(stbuf->st_mode)) {
            stbuf->st_nlink = 2; 
        }

        json_decref(meta_json);
        ret = 0; // Success
        DEBUG_LOG("hpkv_getattr(%s): Successfully populated stat buffer. Mode: %o, Size: %ld\n", path, stbuf->st_mode, stbuf->st_size);
    } else {
        DEBUG_LOG("hpkv_getattr(%s): get_metadata_json returned NULL. Returning -ENOENT.\n", path);
        ret = -ENOENT; // Not found
    }

    DEBUG_LOG("hpkv_getattr: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// readdir: Read directory contents (Modified to filter chunk keys)
static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_readdir: Called for path: %s, offset: %ld\n", path, offset);
    (void) offset; (void) fi;

    char start_key_buf[1024];
    char end_key_buf[1024];
    char api_path[2048];
    char *encoded_start = NULL;
    char *encoded_end = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *records = NULL, *record = NULL;
    json_error_t error;
    int ret = 0;
    size_t i;

    // Use a simple buffer to track added entries to avoid duplicates
    #define MAX_DIR_ENTRIES 512
    char added_entries[MAX_DIR_ENTRIES][256];
    int added_count = 0;

    // Function to check if entry was already added
    int already_added(const char *name) {
        for (int j = 0; j < added_count; ++j) {
            if (strcmp(added_entries[j], name) == 0) return 1;
        }
        return 0;
    }

    // Function to add entry if not already present
    void add_entry(const char *name) {
        if (!already_added(name) && added_count < MAX_DIR_ENTRIES) {
            strncpy(added_entries[added_count], name, 255);
            added_entries[added_count][255] = '\0'; // Ensure null termination
            filler(buf, name, NULL, 0);
            added_count++;
        }
    }

    DEBUG_LOG("hpkv_readdir(%s): Adding '.' and '..'\n", path); // Fixed syntax
    add_entry(".");
    add_entry("..");

    if (strcmp(path, "/") == 0) {
        snprintf(start_key_buf, sizeof(start_key_buf), "/");
    } else {
        snprintf(start_key_buf, sizeof(start_key_buf), "%s/", path);
    }
    // Safely construct end_key_buf
    size_t start_len = strlen(start_key_buf);
    if (start_len + 1 >= sizeof(end_key_buf)) { // Check if space for \xFF and null terminator
        fprintf(stderr, "Error: hpkv_readdir(%s): start_key_buf too long to append suffix.\n", path);
        return -ENAMETOOLONG;
    }
    memcpy(end_key_buf, start_key_buf, start_len);
    end_key_buf[start_len] = '\xFF';
    end_key_buf[start_len + 1] = '\0';

    encoded_start = url_encode(start_key_buf);
    encoded_end = url_encode(end_key_buf);
    if (!encoded_start || !encoded_end || encoded_start[0] == '\0' || encoded_end[0] == '\0') {
        fprintf(stderr, "Error: hpkv_readdir(%s): Failed to URL encode start/end keys.\n", path);
        if (encoded_start) free(encoded_start);
        if (encoded_end) free(encoded_end);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/records?startKey=%s&endKey=%s", encoded_start, encoded_end);
    free(encoded_start); free(encoded_end);

    DEBUG_LOG("hpkv_readdir(%s): Performing GET request for range: %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: hpkv_readdir(%s): Failed to parse JSON response: %s\n", path, error.text);
            return -EIO;
        }
        records = json_object_get(root, "records");
        if (!json_is_array(records)) {
            fprintf(stderr, "Error: hpkv_readdir(%s): JSON response missing 'records' array.\n", path);
            json_decref(root);
            return -EIO;
        }
        DEBUG_LOG("hpkv_readdir(%s): Found %zu records in response.\n", path, json_array_size(records));

        for (i = 0; i < json_array_size(records); i++) {
            record = json_array_get(records, i);
            if (!json_is_object(record)) continue;
            json_t *key_json = json_object_get(record, "key");
            if (!json_is_string(key_json)) continue;

            const char *full_key = json_string_value(key_json);
            DEBUG_LOG("hpkv_readdir(%s): Processing key: %s\n", path, full_key);

            const char *entry_name_ptr = full_key + strlen(start_key_buf);
            if (*entry_name_ptr == '\0') continue; // Skip the directory key itself

            const char *next_slash = strchr(entry_name_ptr, '/');
            char current_entry[256];

            if (next_slash) {
                // Key is inside a subdirectory. Extract the subdir name.
                size_t subdir_len = next_slash - entry_name_ptr;
                if (subdir_len < sizeof(current_entry)) {
                    strncpy(current_entry, entry_name_ptr, subdir_len);
                    current_entry[subdir_len] = '\0';
                    DEBUG_LOG("hpkv_readdir(%s): Adding potential directory entry: %s\n", path, current_entry);
                    add_entry(current_entry); // Add the directory name
                } else {
                    fprintf(stderr, "Warning: hpkv_readdir(%s): Subdirectory name too long: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name_ptr);
                }
            } else {
                // Key is a direct child. Check if it's metadata or chunk.
                if (strstr(entry_name_ptr, ".__meta__") == (entry_name_ptr + strlen(entry_name_ptr) - 9)) {
                    // It's a metadata key. Extract the base name.
                    size_t base_len = strlen(entry_name_ptr) - 9;
                    if (base_len < sizeof(current_entry)) {
                        strncpy(current_entry, entry_name_ptr, base_len);
                        current_entry[base_len] = '\0';
                        DEBUG_LOG("hpkv_readdir(%s): Adding entry from metadata: %s\n", path, current_entry);
                        add_entry(current_entry); // Add the file/dir name
                    } else {
                         fprintf(stderr, "Warning: hpkv_readdir(%s): Base name too long from metadata: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name_ptr);
                    }
                } else if (strstr(entry_name_ptr, ".chunk") == NULL) {
                    // It's not metadata and not a chunk key, assume it's a direct file/object name
                    // (This case might occur if files < CHUNK_SIZE are stored directly? Current logic doesn't do this)
                    if (strlen(entry_name_ptr) < sizeof(current_entry)) {
                        strcpy(current_entry, entry_name_ptr);
                        DEBUG_LOG("hpkv_readdir(%s): Adding direct entry (non-meta, non-chunk): %s\n", path, current_entry);
                        add_entry(current_entry);
                    } else {
                         fprintf(stderr, "Warning: hpkv_readdir(%s): Direct entry name too long: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name_ptr);
                    }
                } else {
                    // It's a chunk key, ignore it for readdir listing.
                    DEBUG_LOG("hpkv_readdir(%s): Ignoring chunk key: %s\n", path, full_key);
                }
            }
        }
        json_decref(root);
    } else {
        if (response.memory) {
             free(response.memory);
             response.memory = NULL;
        }
        fprintf(stderr, "Warning: hpkv_readdir(%s): API GET failed for range, HTTP: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    DEBUG_LOG("hpkv_readdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}


// mkdir: Create a directory (unchanged)
static int hpkv_mkdir(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_mkdir: Called for path: %s, mode: %o\n", path, mode);
    json_t *meta_json = NULL;
    int ret = 0;
    struct fuse_context *context = fuse_get_context();

    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | (mode & 0777)));
    json_object_set_new(meta_json, "uid", json_integer(context ? context->uid : getuid()));
    json_object_set_new(meta_json, "gid", json_integer(context ? context->gid : getgid()));
    json_object_set_new(meta_json, "size", json_integer(0));
    time_t now = time(NULL);
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_mkdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// rmdir: Remove a directory (unchanged, still lacks emptiness check)
static int hpkv_rmdir(const char *path) {
    DEBUG_LOG("hpkv_rmdir: Called for path: %s\n", path);
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // TODO: Add check if directory is empty using readdir logic.

    get_meta_key(path, meta_key, sizeof(meta_key));
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: hpkv_rmdir(%s): Failed to URL encode meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, NULL, 0, &response, 3);
    if (response.memory) {
         free(response.memory);
         response.memory = NULL;
    }
    ret = map_http_to_fuse_error(http_code);

    DEBUG_LOG("hpkv_rmdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// create: Create a new file (Modified for chunking metadata)
static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_create: Called for path: %s, mode: %o\n", path, mode);
    (void) fi;
    json_t *meta_json = NULL;
    int ret = 0;
    struct fuse_context *context = fuse_get_context();

    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFREG | (mode & 0777)));
    json_object_set_new(meta_json, "uid", json_integer(context ? context->uid : getuid()));
    json_object_set_new(meta_json, "gid", json_integer(context ? context->gid : getgid()));
    json_object_set_new(meta_json, "size", json_integer(0)); // Initial size 0
    json_object_set_new(meta_json, "chunk_size", json_integer(HPKV_CHUNK_SIZE)); // Store chunk size
    json_object_set_new(meta_json, "num_chunks", json_integer(0)); // Initial chunk count 0
    time_t now = time(NULL);
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);

    // No need to create empty content key with chunking

    DEBUG_LOG("hpkv_create: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// open: Open a file (Modified to handle O_TRUNC via truncate)
static int hpkv_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_open: Called for path: %s, flags: 0x%x\n", path, fi->flags);
    int res;
    struct stat stbuf;

    res = hpkv_getattr(path, &stbuf);
    if (res != 0) return res;

    if (S_ISDIR(stbuf.st_mode)) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EISDIR;
    }

    if (fi->flags & O_TRUNC) {
        DEBUG_LOG("hpkv_open(%s): O_TRUNC flag set, calling truncate(0).\n", path);
        res = hpkv_truncate(path, 0);
        if (res != 0) {
            fprintf(stderr, "Warning: hpkv_open(%s): Failed to truncate on open: %d\n", path, res);
            // Don't fail open, but log warning.
        }
    }

    DEBUG_LOG("hpkv_open: Finished for path: %s, returning 0\n", path);
    return 0; // Success
}

// read: Read data from a file (Modified for chunking)
static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_read: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi;
    // int ret = 0; // Unused variable removed
    json_t *meta_json = NULL;
    size_t file_size = 0;
    int num_chunks = 0;
    size_t bytes_read_total = 0;

    // 1. Get metadata to find total size and chunk info
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_read(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    json_t *j_val = json_object_get(meta_json, "size");
    if (json_is_integer(j_val)) file_size = (size_t)json_integer_value(j_val);
    else { fprintf(stderr, "Warning: hpkv_read(%s): Missing or invalid 'size' in metadata.\n", path); }

    j_val = json_object_get(meta_json, "num_chunks");
    if (json_is_integer(j_val)) num_chunks = (int)json_integer_value(j_val);
    else { fprintf(stderr, "Warning: hpkv_read(%s): Missing or invalid 'num_chunks' in metadata.\n", path); }
    
    // Chunk size from metadata (or default) - though we use HPKV_CHUNK_SIZE define mostly
    // int chunk_size_meta = HPKV_CHUNK_SIZE;
    // j_val = json_object_get(meta_json, "chunk_size");
    // if (json_is_integer(j_val)) chunk_size_meta = (int)json_integer_value(j_val);

    json_decref(meta_json); // Done with metadata

    DEBUG_LOG("hpkv_read(%s): File size: %zu, Num chunks: %d\n", path, file_size, num_chunks);

    // Check if offset is beyond file size
    if ((size_t)offset >= file_size) {
        DEBUG_LOG("hpkv_read(%s): Offset %ld is beyond file size %zu. Returning 0 bytes.\n", path, offset, file_size);
        return 0; // Read past EOF
    }

    // Calculate start and end chunks needed
    int start_chunk_index = offset / HPKV_CHUNK_SIZE;
    off_t end_offset = offset + size -1; // Inclusive end offset of the read request
    if ((size_t)end_offset >= file_size) {
        end_offset = file_size - 1; // Clamp to actual file end
    }
    int end_chunk_index = (file_size == 0) ? 0 : end_offset / HPKV_CHUNK_SIZE;

    DEBUG_LOG("hpkv_read(%s): Reading from chunk %d to %d.\n", path, start_chunk_index, end_chunk_index);

    // 2. Iterate through required chunks and copy data
    for (int i = start_chunk_index; i <= end_chunk_index; ++i) {
        size_t chunk_content_len = 0;
        char *chunk_content = get_chunk_content(path, i, &chunk_content_len);

        if (!chunk_content || chunk_content_len == 0) {
            // If a chunk is missing or empty (shouldn't happen for middle chunks ideally)
            fprintf(stderr, "Warning: hpkv_read(%s): Chunk %d missing or empty.\n", path, i);
            if (chunk_content) free(chunk_content);
            // Treat as if it contained zeros? Or return error?
            // Let's assume zeros for now, but this indicates inconsistency.
            chunk_content = NULL; // Ensure we don't use freed pointer
            chunk_content_len = 0;
            // If it's the *first* chunk we try to read and it's missing, maybe return error?
            if (i == start_chunk_index && bytes_read_total == 0) {
                 DEBUG_LOG("hpkv_read(%s): First required chunk %d missing. Returning EIO.\n", path, i);
                 return -EIO; // Indicate I/O error if essential chunk missing
            }
        }

        // Calculate the offset within this chunk where reading starts
        off_t chunk_start_offset_global = (off_t)i * HPKV_CHUNK_SIZE;
        off_t read_start_in_chunk = (offset > chunk_start_offset_global) ? (offset - chunk_start_offset_global) : 0;

        // Calculate the offset within this chunk where reading ends (relative to chunk start)
        off_t read_end_in_chunk_global = offset + bytes_read_total + (size - bytes_read_total) - 1;
        if ((size_t)read_end_in_chunk_global >= file_size) read_end_in_chunk_global = file_size - 1;
        off_t read_end_in_chunk = read_end_in_chunk_global - chunk_start_offset_global;
        if (read_end_in_chunk >= (off_t)chunk_content_len) read_end_in_chunk = chunk_content_len - 1;
        
        // Calculate number of bytes to copy from this chunk
        size_t bytes_to_copy_from_chunk = 0;
        if (read_end_in_chunk >= read_start_in_chunk) {
             bytes_to_copy_from_chunk = read_end_in_chunk - read_start_in_chunk + 1;
        }

        // Ensure we don't copy more than remaining buffer space or available chunk data
        if (bytes_to_copy_from_chunk > (size - bytes_read_total)) {
            bytes_to_copy_from_chunk = size - bytes_read_total;
        }
        if (read_start_in_chunk + bytes_to_copy_from_chunk > chunk_content_len) {
             // This case might happen if chunk was missing/shorter than expected
             if (read_start_in_chunk >= (off_t)chunk_content_len) {
                 bytes_to_copy_from_chunk = 0; // Trying to read past end of (missing/short) chunk
             } else {
                 bytes_to_copy_from_chunk = chunk_content_len - read_start_in_chunk;
             }
        }

        DEBUG_LOG("hpkv_read(%s): Chunk %d: len=%zu, read_start=%ld, read_end=%ld, copy_bytes=%zu\n", 
                  path, i, chunk_content_len, read_start_in_chunk, read_end_in_chunk, bytes_to_copy_from_chunk);

        if (bytes_to_copy_from_chunk > 0) {
            if (chunk_content) {
                memcpy(buf + bytes_read_total, chunk_content + read_start_in_chunk, bytes_to_copy_from_chunk);
            } else {
                // If chunk was missing, fill buffer with zeros
                memset(buf + bytes_read_total, 0, bytes_to_copy_from_chunk);
            }
            bytes_read_total += bytes_to_copy_from_chunk;
        }

        if (chunk_content) free(chunk_content);

        // Stop if we have read the requested size
        if (bytes_read_total >= size) {
            break;
        }
    }

    DEBUG_LOG("hpkv_read: Finished for path: %s, returning bytes read %zu\n", path, bytes_read_total);
    return bytes_read_total;
}

// write: Write data to a file (Modified for chunking)
static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_write: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi;
    int ret = 0;
    json_t *meta_json = NULL;
    size_t current_file_size = 0;
    int current_num_chunks = 0;
    size_t bytes_written_total = 0;
    off_t write_end_offset = offset + size; // Exclusive end offset

    // 1. Get current metadata
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_write(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    json_t *j_val = json_object_get(meta_json, "size");
    if (json_is_integer(j_val)) current_file_size = (size_t)json_integer_value(j_val);
    j_val = json_object_get(meta_json, "num_chunks");
    if (json_is_integer(j_val)) current_num_chunks = (int)json_integer_value(j_val);
    // int chunk_size_meta = HPKV_CHUNK_SIZE; // Use define

    DEBUG_LOG("hpkv_write(%s): Current size: %zu, Num chunks: %d\n", path, current_file_size, current_num_chunks);

    // Calculate new potential size and required chunks
    // Use explicit casts for comparisons involving off_t and size_t
    size_t new_potential_size = (write_end_offset > (off_t)current_file_size) ? (size_t)write_end_offset : current_file_size;
    int new_num_chunks = (new_potential_size + HPKV_CHUNK_SIZE - 1) / HPKV_CHUNK_SIZE;
    if (new_potential_size == 0) new_num_chunks = 0; // Special case for empty file

    DEBUG_LOG("hpkv_write(%s): New potential size: %zu, New num chunks: %d\n", path, new_potential_size, new_num_chunks);

    // Calculate start and end chunks affected by this write
    int start_chunk_index = offset / HPKV_CHUNK_SIZE;
    int end_chunk_index = (write_end_offset > 0) ? (write_end_offset - 1) / HPKV_CHUNK_SIZE : 0;
    if (write_end_offset == 0) end_chunk_index = -1; // Handle writing 0 bytes at offset 0

    DEBUG_LOG("hpkv_write(%s): Writing to chunks %d through %d.\n", path, start_chunk_index, end_chunk_index);

    // 2. Iterate through affected chunks
    for (int i = start_chunk_index; i <= end_chunk_index; ++i) {
        size_t chunk_content_len = 0;
        char *current_chunk_content = NULL;
        char new_chunk_data[HPKV_CHUNK_SIZE];
        size_t new_chunk_len = 0;

        // Calculate offsets and lengths relative to this chunk
        off_t chunk_start_offset_global = (off_t)i * HPKV_CHUNK_SIZE;
        off_t write_start_in_chunk = (offset > chunk_start_offset_global) ? (offset - chunk_start_offset_global) : 0;
        size_t bytes_to_write_in_chunk = HPKV_CHUNK_SIZE - write_start_in_chunk;
        if (bytes_to_write_in_chunk > (size - bytes_written_total)) {
            bytes_to_write_in_chunk = size - bytes_written_total;
        }

        DEBUG_LOG("hpkv_write(%s): Chunk %d: write_start=%ld, write_bytes=%zu\n", 
                  path, i, write_start_in_chunk, bytes_to_write_in_chunk);

        // Determine if we need to read the existing chunk
        int need_read = 0;
        if (write_start_in_chunk > 0) need_read = 1; // Writing past the start
        off_t chunk_end_write_offset = write_start_in_chunk + bytes_to_write_in_chunk;
        // If not writing to the very end of the chunk AND the write doesn't reach the file end
        if (chunk_end_write_offset < HPKV_CHUNK_SIZE && 
            (chunk_start_offset_global + chunk_end_write_offset) < (off_t)current_file_size) {
             need_read = 1; 
        }
        // If the chunk potentially exists beyond the current write area (fix comparison)
        if (i < current_num_chunks && 
            (chunk_start_offset_global + HPKV_CHUNK_SIZE) > (off_t)current_file_size && 
            chunk_end_write_offset < (off_t)(current_file_size % HPKV_CHUNK_SIZE)){
             need_read = 1;
        }

        if (need_read) {
            DEBUG_LOG("hpkv_write(%s): Chunk %d: Need to read existing content.\n", path, i);
            current_chunk_content = get_chunk_content(path, i, &chunk_content_len);
            if (!current_chunk_content) {
                // If read fails but we needed it, maybe zero-fill?
                fprintf(stderr, "Warning: hpkv_write(%s): Failed to read chunk %d needed for partial write. Assuming zeros.\n", path, i);
                chunk_content_len = 0;
                // Allocate buffer to hold zeros if needed for prefix
                if (write_start_in_chunk > 0) {
                     current_chunk_content = calloc(write_start_in_chunk, 1);
                     if (current_chunk_content) chunk_content_len = write_start_in_chunk;
                     else { ret = -ENOMEM; goto write_cleanup; }
                } else {
                     current_chunk_content = NULL;
                }
            }
        } else {
             DEBUG_LOG("hpkv_write(%s): Chunk %d: Overwriting or writing new chunk, no read needed.\n", path, i);
             current_chunk_content = NULL;
             chunk_content_len = 0;
        }

        // Prepare the new chunk data
        // Case 1: Overwriting entire chunk or writing new chunk
        if (!need_read) {
            memcpy(new_chunk_data, buf + bytes_written_total, bytes_to_write_in_chunk);
            new_chunk_len = bytes_to_write_in_chunk;
        } 
        // Case 2: Partial write (need prefix and/or suffix)
        else {
            // Determine the final length of the modified chunk
            new_chunk_len = chunk_content_len;
            if (write_start_in_chunk + bytes_to_write_in_chunk > new_chunk_len) {
                new_chunk_len = write_start_in_chunk + bytes_to_write_in_chunk;
            }
            if (new_chunk_len > HPKV_CHUNK_SIZE) new_chunk_len = HPKV_CHUNK_SIZE; // Should not exceed

            // Copy prefix from old chunk if needed
            // Use explicit cast for comparison
            size_t prefix_len = (write_start_in_chunk < (off_t)chunk_content_len) ? (size_t)write_start_in_chunk : chunk_content_len;
            if (prefix_len > 0 && current_chunk_content) {
                memcpy(new_chunk_data, current_chunk_content, prefix_len);
            }
            // Zero fill gap if write starts after current chunk end
            if (write_start_in_chunk > (off_t)chunk_content_len) {
                 memset(new_chunk_data + chunk_content_len, 0, write_start_in_chunk - chunk_content_len);
            }

            // Copy the new data being written
            memcpy(new_chunk_data + write_start_in_chunk, buf + bytes_written_total, bytes_to_write_in_chunk);

            // Copy suffix from old chunk if needed
            size_t suffix_start_in_chunk = write_start_in_chunk + bytes_to_write_in_chunk;
            if (suffix_start_in_chunk < chunk_content_len && current_chunk_content) {
                memcpy(new_chunk_data + suffix_start_in_chunk, 
                       current_chunk_content + suffix_start_in_chunk, 
                       chunk_content_len - suffix_start_in_chunk);
            }
        }

        // Write the modified chunk back to HPKV
        DEBUG_LOG("hpkv_write(%s): Chunk %d: Posting updated content, length %zu.\n", path, i, new_chunk_len);
        ret = post_chunk_content(path, i, new_chunk_data, new_chunk_len);
        if (current_chunk_content) free(current_chunk_content);

        if (ret != 0) {
            fprintf(stderr, "Error: hpkv_write(%s): Failed to post chunk %d. Aborting write. FUSE error: %d\n", path, i, ret);
            goto write_cleanup; // Abort on chunk write failure
        }

        bytes_written_total += bytes_to_write_in_chunk;
    }

    // 3. Update metadata (size, num_chunks, mtime, ctime)
    DEBUG_LOG("hpkv_write(%s): All chunks written. Updating metadata...\n", path);
    time_t now = time(NULL);
    json_object_set_new(meta_json, "size", json_integer(new_potential_size));
    json_object_set_new(meta_json, "num_chunks", json_integer(new_num_chunks));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json); // Takes ownership of meta_json
    meta_json = NULL; // Avoid double decref in cleanup
    if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_write(%s): Failed to update metadata after writing content (FUSE error %d). Metadata might be inconsistent.\n", path, ret);
        // Return bytes written, but log warning.
    }

write_cleanup:
    if (meta_json) json_decref(meta_json); // Decref if not consumed by post_metadata_json

    if (ret == 0) {
        DEBUG_LOG("hpkv_write: Finished for path: %s, returning written size %zu\n", path, size);
        return size; // Return number of bytes requested to write on success
    } else {
        DEBUG_LOG("hpkv_write: Finished for path: %s with error, returning %d\n", path, ret);
        return ret; // Return negative error code on failure
    }
}

// truncate: Change the size of a file (Modified for chunking)
static int hpkv_truncate(const char *path, off_t size) {
    DEBUG_LOG("hpkv_truncate: Called for path: %s, size: %ld\n", path, size);
    int ret = 0;
    json_t *meta_json = NULL;
    size_t current_file_size = 0;
    int current_num_chunks = 0;
    size_t new_size = (size_t)size;

    if (size < 0) return -EINVAL;

    // 1. Get current metadata
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_truncate(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    json_t *j_val = json_object_get(meta_json, "size");
    if (json_is_integer(j_val)) current_file_size = (size_t)json_integer_value(j_val);
    j_val = json_object_get(meta_json, "num_chunks");
    if (json_is_integer(j_val)) current_num_chunks = (int)json_integer_value(j_val);

    DEBUG_LOG("hpkv_truncate(%s): Current size: %zu, Num chunks: %d. Target size: %zu\n", 
              path, current_file_size, current_num_chunks, new_size);

    // If size is the same, just update times
    if (current_file_size == new_size) {
        DEBUG_LOG("hpkv_truncate(%s): Size unchanged. Updating metadata times only.\n", path);
        goto update_metadata_only;
    }

    // Calculate new number of chunks
    int new_num_chunks = (new_size + HPKV_CHUNK_SIZE - 1) / HPKV_CHUNK_SIZE;
    if (new_size == 0) new_num_chunks = 0;

    DEBUG_LOG("hpkv_truncate(%s): New num chunks: %d\n", path, new_num_chunks);

    // 2. Handle shrinking
    if (new_size < current_file_size) {
        DEBUG_LOG("hpkv_truncate(%s): Shrinking file.\n", path);
        // Delete chunks beyond the new end
        for (int i = new_num_chunks; i < current_num_chunks; ++i) {
            DEBUG_LOG("hpkv_truncate(%s): Deleting chunk %d\n", path, i);
            ret = delete_chunk_content(path, i);
            if (ret != 0) {
                fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to delete chunk %d during shrink (FUSE %d). Continuing...\n", path, i, ret);
                // Continue deleting other chunks if possible
            }
        }
        // Truncate the last remaining chunk if necessary
        if (new_num_chunks > 0) {
            int last_chunk_index = new_num_chunks - 1;
            size_t size_in_last_chunk = new_size % HPKV_CHUNK_SIZE;
            if (size_in_last_chunk == 0 && new_size > 0) size_in_last_chunk = HPKV_CHUNK_SIZE; // Full last chunk
            
            size_t current_last_chunk_len = 0;
            char *last_chunk_content = get_chunk_content(path, last_chunk_index, &current_last_chunk_len);

            if (last_chunk_content) {
                if (current_last_chunk_len > size_in_last_chunk) {
                    DEBUG_LOG("hpkv_truncate(%s): Truncating last chunk %d from %zu to %zu bytes.\n", 
                              path, last_chunk_index, current_last_chunk_len, size_in_last_chunk);
                    ret = post_chunk_content(path, last_chunk_index, last_chunk_content, size_in_last_chunk);
                    if (ret != 0) {
                         fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to post truncated last chunk %d (FUSE %d).\n", path, last_chunk_index, ret);
                    }
                } else {
                     DEBUG_LOG("hpkv_truncate(%s): Last chunk %d size (%zu) already <= target size in chunk (%zu). No content change needed.\n", 
                               path, last_chunk_index, current_last_chunk_len, size_in_last_chunk);
                }
                free(last_chunk_content);
            } else {
                 fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to get last chunk %d content during shrink.\n", path, last_chunk_index);
                 // If we couldn't get the last chunk, we can't truncate it. Metadata update will reflect new size.
            }
        }
    }
    // 3. Handle extending
    else { // new_size > current_file_size
        DEBUG_LOG("hpkv_truncate(%s): Extending file.\n", path);
        // Zero-pad the last existing chunk if needed
        if (current_num_chunks > 0) {
            int last_chunk_index = current_num_chunks - 1;
            size_t size_in_last_chunk = current_file_size % HPKV_CHUNK_SIZE;
            if (size_in_last_chunk == 0 && current_file_size > 0) size_in_last_chunk = HPKV_CHUNK_SIZE;

            if (size_in_last_chunk < HPKV_CHUNK_SIZE) {
                size_t current_last_chunk_len = 0;
                char *last_chunk_content = get_chunk_content(path, last_chunk_index, &current_last_chunk_len);
                if (last_chunk_content) {
                    if (current_last_chunk_len < HPKV_CHUNK_SIZE) {
                        size_t bytes_to_pad = HPKV_CHUNK_SIZE - current_last_chunk_len;
                        // Only pad up to the end of the chunk if the new size is within this chunk
                        if (last_chunk_index == new_num_chunks - 1) {
                             size_t final_size_in_chunk = new_size % HPKV_CHUNK_SIZE;
                             if (final_size_in_chunk == 0) final_size_in_chunk = HPKV_CHUNK_SIZE;
                             if (final_size_in_chunk < HPKV_CHUNK_SIZE) {
                                 bytes_to_pad = final_size_in_chunk - current_last_chunk_len;
                             }
                        }
                        if (bytes_to_pad > 0) {
                            DEBUG_LOG("hpkv_truncate(%s): Padding last chunk %d from %zu with %zu zeros.\n", 
                                      path, last_chunk_index, current_last_chunk_len, bytes_to_pad);
                            char *padded_chunk = malloc(current_last_chunk_len + bytes_to_pad);
                            if (padded_chunk) {
                                memcpy(padded_chunk, last_chunk_content, current_last_chunk_len);
                                memset(padded_chunk + current_last_chunk_len, 0, bytes_to_pad);
                                ret = post_chunk_content(path, last_chunk_index, padded_chunk, current_last_chunk_len + bytes_to_pad);
                                free(padded_chunk);
                                if (ret != 0) {
                                     fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to post padded last chunk %d (FUSE %d).\n", path, last_chunk_index, ret);
                                }
                            } else { ret = -ENOMEM; }
                        }
                    }
                    free(last_chunk_content);
                    if (ret != 0) goto truncate_cleanup; // Abort if padding failed
                } else {
                     fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to get last chunk %d content during extend padding.\n", path, last_chunk_index);
                }
            }
        }
        // Create new zero-filled chunks if needed
        char zero_chunk[HPKV_CHUNK_SIZE];
        memset(zero_chunk, 0, HPKV_CHUNK_SIZE);
        for (int i = current_num_chunks; i < new_num_chunks; ++i) {
            size_t size_to_write = HPKV_CHUNK_SIZE;
            if (i == new_num_chunks - 1) { // Last new chunk
                size_t size_in_last_chunk = new_size % HPKV_CHUNK_SIZE;
                if (size_in_last_chunk == 0 && new_size > 0) size_in_last_chunk = HPKV_CHUNK_SIZE;
                size_to_write = size_in_last_chunk;
            }
            if (size_to_write > 0) {
                 DEBUG_LOG("hpkv_truncate(%s): Creating new zero chunk %d, size %zu\n", path, i, size_to_write);
                 ret = post_chunk_content(path, i, zero_chunk, size_to_write);
                 if (ret != 0) {
                     fprintf(stderr, "Error: hpkv_truncate(%s): Failed to post new zero chunk %d (FUSE %d). Aborting extend.\n", path, i, ret);
                     // Should we try to delete previously created chunks?
                     goto truncate_cleanup;
                 }
            }
        }
    }

update_metadata_only:
    // 4. Update metadata (size, num_chunks, mtime, ctime)
    DEBUG_LOG("hpkv_truncate(%s): Updating metadata... New size: %zu, New num_chunks: %d\n", path, new_size, new_num_chunks);
    time_t now = time(NULL);
    json_object_set_new(meta_json, "size", json_integer(new_size));
    json_object_set_new(meta_json, "num_chunks", json_integer(new_num_chunks));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json); // Takes ownership of meta_json
    meta_json = NULL; // Avoid double decref
    if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to update metadata after truncating content (FUSE error %d).\n", path, ret);
        // Return success for truncate itself, but log warning.
        ret = 0;
    }

truncate_cleanup:
    if (meta_json) json_decref(meta_json);

    DEBUG_LOG("hpkv_truncate: Finished for path: %s, returning %d\n", path, ret);
    return ret; // Return 0 on success, error code otherwise
}

// unlink: Delete a file (Modified for chunking)
static int hpkv_unlink(const char *path) {
    DEBUG_LOG("hpkv_unlink: Called for path: %s\n", path);
    char meta_key[1024];
    char api_path_meta[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response_meta;
    long http_code_meta;
    int ret_meta = 0, ret_chunks = 0;
    json_t *meta_json = NULL;
    int num_chunks = 0;

    // 1. Get metadata to find number of chunks
    meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_val = json_object_get(meta_json, "num_chunks");
        if (json_is_integer(j_val)) num_chunks = (int)json_integer_value(j_val);
        json_decref(meta_json);
        DEBUG_LOG("hpkv_unlink(%s): Found %d chunks from metadata.\n", path, num_chunks);
    } else {
        DEBUG_LOG("hpkv_unlink(%s): Metadata not found. Assuming file doesn't exist or has no chunks.\n", path);
        // If metadata doesn't exist, the file doesn't exist. Return ENOENT.
        return -ENOENT;
    }

    // 2. Delete all chunk keys
    for (int i = 0; i < num_chunks; ++i) {
        int chunk_del_ret = delete_chunk_content(path, i);
        if (chunk_del_ret != 0) {
            fprintf(stderr, "Warning: hpkv_unlink(%s): Failed to delete chunk %d (FUSE %d). Continuing...\n", path, i, chunk_del_ret);
            if (ret_chunks == 0) ret_chunks = chunk_del_ret; // Store first chunk deletion error
        }
    }

    // 3. Delete the metadata key
    get_meta_key(path, meta_key, sizeof(meta_key));
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: hpkv_unlink(%s): Failed to URL encode meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return (ret_chunks != 0) ? ret_chunks : -EIO; // Return chunk error or EIO
    }
    snprintf(api_path_meta, sizeof(api_path_meta), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("hpkv_unlink(%s): Performing DELETE request for metadata: %s\n", path, api_path_meta);
    http_code_meta = perform_hpkv_request_with_retry("DELETE", api_path_meta, NULL, NULL, 0, &response_meta, 3);
    if (response_meta.memory) {
        free(response_meta.memory);
        response_meta.memory = NULL; // Fix indentation warning
    }
    ret_meta = map_http_to_fuse_error(http_code_meta);
    if (ret_meta != 0 && ret_meta != -ENOENT) {
        fprintf(stderr, "Warning: hpkv_unlink(%s): Failed DELETE for metadata %s, HTTP: %ld, FUSE: %d\n", path, meta_key, http_code_meta, ret_meta);
    } else if (ret_meta == -ENOENT) {
        ret_meta = 0; // Treat metadata not found as success if chunks were deleted (or didn't exist)
    }

    // Return success only if metadata delete succeeded (or ENOENT) AND chunk deletes succeeded (or ENOENT)
    // Prioritize returning metadata error if it occurred.
    int final_ret = (ret_meta != 0) ? ret_meta : ret_chunks;
    DEBUG_LOG("hpkv_unlink: Finished for path: %s, returning %d\n", path, final_ret);
    return final_ret;
}

// rename: Rename/move a file or directory (Modified for chunking)
// Note: Still NOT atomic.
static int hpkv_rename(const char *from, const char *to) {
    DEBUG_LOG("hpkv_rename: Called from: %s, to: %s\n", from, to);
    struct stat stbuf;
    int ret = 0;
    json_t *meta_json = NULL;
    int num_chunks = 0;

    // 1. Get attributes of the source
    ret = hpkv_getattr(from, &stbuf);
    if (ret != 0) return ret;

    // 2. Check destination
    struct stat stbuf_to;
    int to_exists = (hpkv_getattr(to, &stbuf_to) == 0);
    if (to_exists) {
        if (S_ISDIR(stbuf.st_mode)) return -EEXIST;
        if (S_ISDIR(stbuf_to.st_mode)) return -EISDIR;
        ret = hpkv_unlink(to);
        if (ret != 0) {
            fprintf(stderr, "Error: hpkv_rename: Failed to delete existing destination file %s (%d).\n", to, ret);
            return ret;
        }
    }

    // 3. Copy metadata from 'from' to 'to'
    DEBUG_LOG("hpkv_rename: Copying metadata from %s to %s\n", from, to);
    meta_json = get_metadata_json(from);
    if (!meta_json) {
        fprintf(stderr, "Error: hpkv_rename: Failed to get metadata for source %s!\n", from);
        return -EIO;
    }
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));
    // Get num_chunks for later use
    json_t *j_val = json_object_get(meta_json, "num_chunks");
    if (json_is_integer(j_val)) num_chunks = (int)json_integer_value(j_val);
    
    ret = post_metadata_json(to, meta_json); // Takes ownership of meta_json
    meta_json = NULL; // Avoid double decref
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_rename: Failed to post metadata for destination %s (%d).\n", to, ret);
        return ret;
    }

    // 4. If it's a file, copy chunks from 'from' to 'to'
    if (S_ISREG(stbuf.st_mode)) {
        DEBUG_LOG("hpkv_rename: Source %s is a file with %d chunks. Copying chunks to %s\n", from, num_chunks, to);
        for (int i = 0; i < num_chunks; ++i) {
            size_t chunk_len = 0;
            char *chunk_content = get_chunk_content(from, i, &chunk_len);
            if (chunk_content) {
                DEBUG_LOG("hpkv_rename: Copying chunk %d (len %zu) from %s to %s\n", i, chunk_len, from, to);
                ret = post_chunk_content(to, i, chunk_content, chunk_len);
                free(chunk_content);
                if (ret != 0) {
                    fprintf(stderr, "Error: hpkv_rename: Failed to post chunk %d to destination %s (%d).\n", i, to, ret);
                    hpkv_unlink(to); // Attempt cleanup of destination
                    return ret;
                }
            } else {
                // If a source chunk is missing, should we create an empty one at dest or fail?
                fprintf(stderr, "Warning: hpkv_rename: Failed to get chunk %d from source %s during rename. Skipping chunk copy.\n", i, from);
                // Let's skip copying this chunk, the destination might be incomplete.
            }
        }
    } else {
         DEBUG_LOG("hpkv_rename: Source %s is a directory. Renaming metadata only.\n", from);
    }

    // 5. Delete the old metadata and chunks (if file)
    DEBUG_LOG("hpkv_rename: Deleting original path %s\n", from);
    // We need to pass the original num_chunks to unlink
    // Re-reading metadata just before unlink is safer in case of interruption
    int unlink_ret = hpkv_unlink(from); 
    if (unlink_ret != 0) {
        fprintf(stderr, "Warning: hpkv_rename: Failed to delete original path %s after renaming (%d). Destination %s might be a duplicate.\n", from, unlink_ret, to);
        // Don't return error for the rename itself, but log warning.
    }

    DEBUG_LOG("hpkv_rename: Finished from %s to %s, returning %d\n", from, to, ret);
    return ret; // Return 0 if copy succeeded, even if cleanup failed
}

// chmod: Change file permissions (unchanged)
static int hpkv_chmod(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_chmod: Called for path: %s, mode: %o\n", path, mode);
    json_t *meta_json = NULL;
    int ret = 0;

    meta_json = get_metadata_json(path);
    if (!meta_json) return -ENOENT;

    mode_t current_mode = 0;
    json_t *j_val = json_object_get(meta_json, "mode");
    if (json_is_integer(j_val)) current_mode = (mode_t)json_integer_value(j_val);
    else current_mode = S_IFREG | 0644; 

    mode_t new_mode = (current_mode & S_IFMT) | (mode & ~S_IFMT);
    json_object_set_new(meta_json, "mode", json_integer(new_mode));
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_chmod: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// chown: Change file owner/group (unchanged)
static int hpkv_chown(const char *path, uid_t uid, gid_t gid) {
    DEBUG_LOG("hpkv_chown: Called for path: %s, uid: %d, gid: %d\n", path, (int)uid, (int)gid);
    json_t *meta_json = NULL;
    int ret = 0;

    meta_json = get_metadata_json(path);
    if (!meta_json) return -ENOENT;

    if (uid != (uid_t)-1) json_object_set_new(meta_json, "uid", json_integer(uid));
    if (gid != (gid_t)-1) json_object_set_new(meta_json, "gid", json_integer(gid));
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_chown: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// utimens: Change file access/modification times (unchanged)
static int hpkv_utimens(const char *path, const struct timespec ts[2]) {
    DEBUG_LOG("hpkv_utimens: Called for path: %s\n", path);
    json_t *meta_json = NULL;
    int ret = 0;

    meta_json = get_metadata_json(path);
    if (!meta_json) return -ENOENT;

    if (ts[0].tv_nsec != UTIME_OMIT) json_object_set_new(meta_json, "atime", json_integer(ts[0].tv_sec));
    if (ts[1].tv_nsec != UTIME_OMIT) json_object_set_new(meta_json, "mtime", json_integer(ts[1].tv_sec));
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_utimens: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// --- FUSE Setup ---

static struct fuse_operations hpkv_oper = {
    .getattr   = hpkv_getattr,
    .readdir   = hpkv_readdir,
    .mkdir     = hpkv_mkdir,
    .rmdir     = hpkv_rmdir,
    .create    = hpkv_create,
    .open      = hpkv_open,
    .read      = hpkv_read,
    .write     = hpkv_write,
    .truncate  = hpkv_truncate,
    .unlink    = hpkv_unlink,
    .rename    = hpkv_rename,
    .chmod     = hpkv_chmod,
    .chown     = hpkv_chown,
    .utimens   = hpkv_utimens,
    // Add other operations as needed (e.g., symlink, link, statfs)
};

// Define command line options
#define HPKV_OPT(t, p, v) { t, offsetof(struct hpkv_options, p), v }

static struct fuse_opt hpkv_opts[] = {
    HPKV_OPT("--api-url=%s", api_base_url, 0),
    HPKV_OPT("--api-key=%s", api_key, 0),
    FUSE_OPT_END
};

// Option parsing callback for FUSE
static int hpkv_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    (void) data; (void) outargs; (void) arg;
    switch (key) {
        case FUSE_OPT_KEY_OPT: return 1;
        case FUSE_OPT_KEY_NONOPT: return 1;
        default: return 0;
    }
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct hpkv_options options = {0};
    hpkv_config config = {0};
    int ret;

    fprintf(stderr, "Starting HPKV FUSE filesystem (hpkvfs v0.1.2 - Chunking).\n");

    if (fuse_opt_parse(&args, &options, hpkv_opts, hpkv_opt_proc) == -1) {
        fprintf(stderr, "Error: Failed to parse FUSE options.\n");
        return 1;
    }
    if (!options.api_base_url || !options.api_key) {
        fprintf(stderr, "Error: --api-url and --api-key are required.\nUsage: %s <mountpoint> --api-url=<url> --api-key=<key> [FUSE options]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }

    config.api_base_url = strdup(options.api_base_url);
    config.api_key = strdup(options.api_key);
    if (!config.api_base_url || !config.api_key) {
        fprintf(stderr, "Error: Failed to allocate memory for config.\n");
        if (config.api_base_url) free(config.api_base_url);
        if (config.api_key) free(config.api_key);
        fuse_opt_free_args(&args);
        return 1;
    }

    fprintf(stderr, "  API URL: %s\n", config.api_base_url);
    fprintf(stderr, "  Chunk Size: %d bytes\n", HPKV_CHUNK_SIZE);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    fprintf(stderr, "Mounting filesystem...\n");

    ret = fuse_main(args.argc, args.argv, &hpkv_oper, &config);

    fprintf(stderr, "Filesystem unmounted. Exiting with status %d.\n", ret);

    curl_global_cleanup();
    free(config.api_base_url);
    free(config.api_key);
    fuse_opt_free_args(&args);

    return ret;
}

