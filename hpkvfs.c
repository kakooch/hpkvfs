/*******************************************************************************
 * HPKV FUSE Filesystem
 * 
 * Connects to an HPKV REST API to provide a filesystem interface.
 * Supports Linux (primary) and experimental macOS (macFUSE).
 * Windows support requires significant porting (Dokan/WinFsp).
 * 
 * Implements file chunking to handle API value size limits.
 * Automatically initializes root directory metadata if missing.
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

// Global pointer for config, needed for early init check
static hpkv_config global_hpkv_config;

// Get private data from FUSE context (use global_hpkv_config for early init)
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
    // Use global config here as FUSE context might not be ready during early init
    snprintf(full_url, sizeof(full_url), "%s%s", global_hpkv_config.api_base_url, path_segment);
    DEBUG_LOG("perform_hpkv_request: Full URL=%s\n", full_url);

    // Set common options
    curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response_chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "hpkvfs/0.1.4"); // Version bump
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connection timeout
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 60L);      // 60 seconds total timeout (increased for potentially larger ops)
    // Consider adding CURLOPT_FOLLOWLOCATION, 1L if redirects are expected/needed

    // Set headers
    // Use global config here as FUSE context might not be ready during early init
    snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", global_hpkv_config.api_key);
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
        if (path_len > 1 && path[path_len - 1] == '/') path_len--; // Trim trailing slash if present
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

    // Use global config here as FUSE context might not be ready during early init
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
        fprintf(stderr, "Error: get_metadata_json(%s): API config not initialized!\n", path);
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
        return NULL;
    }
}

// Helper to post metadata JSON object for a path.
// Returns 0 on success, or a negative FUSE error code on failure.
static int post_metadata_json(const char *path, json_t *meta_json) {
    DEBUG_LOG("post_metadata_json: Entered for path: %s\n", path);
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    char *inner_json_str = NULL;
    char *outer_json_str = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // Use global config here as FUSE context might not be ready during early init
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
        fprintf(stderr, "Error: post_metadata_json(%s): API config not initialized!\n", path);
        return -EIO;
    }

    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("post_metadata_json: Meta key: %s\n", meta_key);
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: post_metadata_json(%s): URL encoding failed for meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record"); // POST to /record endpoint

    // Dump the inner metadata object to a string
    inner_json_str = json_dumps(meta_json, JSON_COMPACT);
    if (!inner_json_str) {
        fprintf(stderr, "Error: post_metadata_json(%s): Failed to dump inner metadata to JSON string.\n", path);
        free(encoded_key);
        return -EIO;
    }

    // Create the outer JSON object: {"key": "<meta_key>", "value": "<inner_json_str>"}
    json_t *outer_json = json_object();
    if (!outer_json) {
        fprintf(stderr, "Error: post_metadata_json(%s): Failed to create outer JSON object.\n", path);
        free(inner_json_str);
        free(encoded_key);
        return -EIO;
    }
    json_object_set_new(outer_json, "key", json_string(meta_key));
    json_object_set_new(outer_json, "value", json_string(inner_json_str));
    free(inner_json_str); // Value string is now owned by outer_json

    // Dump the outer JSON object to a string for the request body
    outer_json_str = json_dumps(outer_json, JSON_COMPACT);
    json_decref(outer_json);
    if (!outer_json_str) {
        fprintf(stderr, "Error: post_metadata_json(%s): Failed to dump outer JSON to string.\n", path);
        free(encoded_key);
        return -EIO;
    }

    DEBUG_LOG("post_metadata_json: Performing POST request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("POST", api_path, outer_json_str, NULL, 0, &response, 3);
    free(outer_json_str);
    free(encoded_key);

    if (http_code >= 200 && http_code < 300) {
        DEBUG_LOG("post_metadata_json(%s): Successfully posted metadata.\n", path);
        ret = 0;
    } else {
        fprintf(stderr, "Error: post_metadata_json(%s): API POST failed, HTTP: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    if (response.memory) {
        free(response.memory); // Free response memory if any
    }
    return ret;
}

// Helper to delete a key (metadata or chunk)
// Returns 0 on success or 404, negative FUSE error code otherwise.
static int delete_hpkv_key(const char *key) {
    DEBUG_LOG("delete_hpkv_key: Entered for key: %s\n", key);
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // Use global config here as FUSE context might not be ready during early init
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
        fprintf(stderr, "Error: delete_hpkv_key(%s): API config not initialized!\n", key);
        return -EIO;
    }

    encoded_key = url_encode(key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: delete_hpkv_key(%s): URL encoding failed.\n", key);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("delete_hpkv_key: Performing DELETE request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 204 || http_code == 404) { // Success or Not Found are okay for delete
        DEBUG_LOG("delete_hpkv_key(%s): DELETE successful or key not found (HTTP: %ld).\n", key, http_code);
        ret = 0;
    } else {
        fprintf(stderr, "Error: delete_hpkv_key(%s): API DELETE failed, HTTP: %ld\n", key, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    if (response.memory) {
        free(response.memory); // Free response memory if any
    }
    return ret;
}

// Helper to get chunk content.
// Returns a MemoryStruct with content (caller must free memory) or NULL memory on error/not found.
static struct MemoryStruct get_chunk_content(const char *base_path, int chunk_index) {
    DEBUG_LOG("get_chunk_content: Entered for path: %s, chunk: %d\n", base_path, chunk_index);
    char chunk_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL;
    json_error_t error;

    // Initialize response to safe state
    response.memory = NULL;
    response.size = 0;

    // Use global config here as FUSE context might not be ready during early init
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
        fprintf(stderr, "Error: get_chunk_content(%s, %d): API config not initialized!\n", base_path, chunk_index);
        return response;
    }

    get_chunk_key(base_path, chunk_index, chunk_key, sizeof(chunk_key));
    DEBUG_LOG("get_chunk_content: Chunk key: %s\n", chunk_key);
    encoded_key = url_encode(chunk_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: get_chunk_content(%s, %d): URL encoding failed for chunk key.\n", base_path, chunk_index);
        if (encoded_key) free(encoded_key);
        return response;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("get_chunk_content: Performing GET request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL; // Reset response struct
        response.size = 0;
        if (!root) {
            fprintf(stderr, "Error: get_chunk_content(%s, %d): Failed to parse outer JSON response: %s\n", base_path, chunk_index, error.text);
            return response;
        }
        json_t *value_json = json_object_get(root, "value");
        if (!json_is_string(value_json)) {
            fprintf(stderr, "Error: get_chunk_content(%s, %d): API response missing 'value' string.\n", base_path, chunk_index);
            json_decref(root);
            return response;
        }
        // We need the raw string content, potentially binary.
        // Jansson stores strings with null termination, but size might be needed.
        // Let's duplicate the string and get its length from Jansson.
        const char *value_str = json_string_value(value_json);
        size_t value_len = json_string_length(value_json);
        
        response.memory = malloc(value_len + 1); // +1 for safety, though Jansson might include it
        if (!response.memory) {
             fprintf(stderr, "Error: get_chunk_content(%s, %d): Failed to allocate memory for chunk content.\n", base_path, chunk_index);
             json_decref(root);
             return response;
        }
        memcpy(response.memory, value_str, value_len);
        response.memory[value_len] = '\0'; // Ensure null termination
        response.size = value_len;

        json_decref(root);
        DEBUG_LOG("get_chunk_content(%s, %d): Successfully retrieved chunk content (size %zu).\n", base_path, chunk_index, response.size);
        return response; // Return the actual chunk content
    } else {
        if (response.memory) {
             free(response.memory);
             response.memory = NULL;
        }
        if (http_code != 404) {
             fprintf(stderr, "Warning: get_chunk_content: API GET failed for %s, HTTP: %ld\n", chunk_key, http_code);
        }
        DEBUG_LOG("get_chunk_content: API GET failed or returned non-200 status (%ld). Returning empty response.\n", http_code);
        return response; // Return empty response on error/not found
    }
}

// Helper to post chunk content.
// Returns 0 on success, or a negative FUSE error code on failure.
static int post_chunk_content(const char *base_path, int chunk_index, const char *content, size_t content_len) {
    DEBUG_LOG("post_chunk_content: Entered for path: %s, chunk: %d, len: %zu\n", base_path, chunk_index, content_len);
    char chunk_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    char *outer_json_str = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // Use global config here as FUSE context might not be ready during early init
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): API config not initialized!\n", base_path, chunk_index);
        return -EIO;
    }

    get_chunk_key(base_path, chunk_index, chunk_key, sizeof(chunk_key));
    DEBUG_LOG("post_chunk_content: Chunk key: %s\n", chunk_key);
    encoded_key = url_encode(chunk_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): URL encoding failed for chunk key.\n", base_path, chunk_index);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record"); // POST to /record endpoint

    // Create the outer JSON object: {"key": "<chunk_key>", "value": "<content_string>"}
    json_t *outer_json = json_object();
    if (!outer_json) {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): Failed to create outer JSON object.\n", base_path, chunk_index);
        free(encoded_key);
        return -EIO;
    }
    json_object_set_new(outer_json, "key", json_string(chunk_key));
    // Use json_stringn for potentially binary data
    json_object_set_new(outer_json, "value", json_stringn(content, content_len)); 

    // Dump the outer JSON object to a string for the request body
    outer_json_str = json_dumps(outer_json, JSON_COMPACT | JSON_ENSURE_ASCII); // Ensure ASCII for safety?
    json_decref(outer_json);
    if (!outer_json_str) {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): Failed to dump outer JSON to string.\n", base_path, chunk_index);
        free(encoded_key);
        return -EIO;
    }

    DEBUG_LOG("post_chunk_content: Performing POST request for %s\n", api_path);
    // Use the outer_json_str as the request body
    http_code = perform_hpkv_request_with_retry("POST", api_path, outer_json_str, NULL, 0, &response, 3);
    free(outer_json_str);
    free(encoded_key);

    if (http_code >= 200 && http_code < 300) {
        DEBUG_LOG("post_chunk_content(%s, %d): Successfully posted chunk content.\n", base_path, chunk_index);
        ret = 0;
    } else {
        fprintf(stderr, "Error: post_chunk_content(%s, %d): API POST failed, HTTP: %ld\n", base_path, chunk_index, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    if (response.memory) {
        free(response.memory); // Free response memory if any
    }
    return ret;
}

// --- Automatic Root Initialization ---

// Creates default metadata for the root directory
static int create_default_root_metadata() {
    DEBUG_LOG("create_default_root_metadata: Attempting to create default root metadata.\n");
    json_t *meta_json = json_object();
    if (!meta_json) {
        fprintf(stderr, "Error: create_default_root_metadata: Failed to create JSON object.\n");
        return -ENOMEM;
    }

    time_t now = time(NULL);
    uid_t uid = getuid(); // Use current user's UID
    gid_t gid = getgid(); // Use current user's GID

    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | 0755));
    json_object_set_new(meta_json, "uid", json_integer(uid));
    json_object_set_new(meta_json, "gid", json_integer(gid));
    json_object_set_new(meta_json, "size", json_integer(0)); // Directories have 0 size
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));
    json_object_set_new(meta_json, "num_chunks", json_integer(0)); // No chunks for directory
    json_object_set_new(meta_json, "chunk_size", json_integer(HPKV_CHUNK_SIZE));

    int ret = post_metadata_json("/", meta_json);
    json_decref(meta_json);

    if (ret == 0) {
        DEBUG_LOG("create_default_root_metadata: Successfully created default root metadata.\n");
    } else {
        fprintf(stderr, "Error: create_default_root_metadata: Failed to post default root metadata (Error %d).\n", ret);
    }
    return ret;
}

// Checks if root metadata exists and creates it if not.
// Returns 0 on success (exists or created), negative error code on failure.
static int ensure_root_metadata_exists() {
    DEBUG_LOG("ensure_root_metadata_exists: Checking for root metadata...\n");
    json_t *meta_json = get_metadata_json("/");
    if (meta_json) {
        DEBUG_LOG("ensure_root_metadata_exists: Root metadata found.\n");
        json_decref(meta_json);
        return 0; // Root exists
    } else {
        // Check if the error was specifically ENOENT (404)
        // Note: get_metadata_json returns NULL for various errors, not just 404.
        // We rely on the fact that if it's NULL, we should try creating it.
        DEBUG_LOG("ensure_root_metadata_exists: Root metadata not found or error retrieving. Attempting creation...\n");
        return create_default_root_metadata();
    }
}

// --- FUSE Operations Implementation ---

static int hpkv_getattr(const char *path, struct stat *stbuf) {
    DEBUG_LOG("hpkv_getattr: Entered for path: %s\n", path);
    memset(stbuf, 0, sizeof(struct stat));
    json_t *meta_json = NULL;
    int ret = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_getattr(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_getattr(%s): Metadata not found or error retrieving. Returning ENOENT.\n", path);
        return -ENOENT;
    }

    // Populate stat buffer from JSON
    stbuf->st_mode = (mode_t)json_integer_value(json_object_get(meta_json, "mode"));
    stbuf->st_uid = (uid_t)json_integer_value(json_object_get(meta_json, "uid"));
    stbuf->st_gid = (gid_t)json_integer_value(json_object_get(meta_json, "gid"));
    stbuf->st_size = (off_t)json_integer_value(json_object_get(meta_json, "size"));
    stbuf->st_atime = (time_t)json_integer_value(json_object_get(meta_json, "atime"));
    stbuf->st_mtime = (time_t)json_integer_value(json_object_get(meta_json, "mtime"));
    stbuf->st_ctime = (time_t)json_integer_value(json_object_get(meta_json, "ctime"));

    // Set nlink based on type (simplified)
    if (S_ISDIR(stbuf->st_mode)) {
        stbuf->st_nlink = 2; // Directories typically have at least 2 links (. and ..)
    } else {
        stbuf->st_nlink = 1;
    }

    // Set block size (optional, can affect performance reporting)
    stbuf->st_blksize = 4096;
    stbuf->st_blocks = (stbuf->st_size + 511) / 512; // Number of 512B blocks

    DEBUG_LOG("hpkv_getattr(%s): Success. Mode=%o, Size=%ld\n", path, stbuf->st_mode, stbuf->st_size);
    json_decref(meta_json);
    return ret;
}

static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    (void) offset; // Unused parameter
    (void) fi;     // Unused parameter
    DEBUG_LOG("hpkv_readdir: Entered for path: %s\n", path);
    char api_path[2048];
    char *encoded_prefix = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *keys_array = NULL;
    json_error_t error;
    int ret = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_readdir(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    // Add '.' and '..'
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // Construct prefix for listing keys
    char prefix[1024];
    if (strcmp(path, "/") == 0) {
        snprintf(prefix, sizeof(prefix), "/"); // List keys starting with /
    } else {
        snprintf(prefix, sizeof(prefix), "%s/", path); // List keys starting with /dir/
    }
    DEBUG_LOG("hpkv_readdir: Listing prefix: %s\n", prefix);
    encoded_prefix = url_encode(prefix);
    if (!encoded_prefix || encoded_prefix[0] == '\0') {
        fprintf(stderr, "Error: hpkv_readdir(%s): URL encoding failed for prefix.\n", path);
        if (encoded_prefix) free(encoded_prefix);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/keys?prefix=%s", encoded_prefix);
    free(encoded_prefix);

    DEBUG_LOG("hpkv_readdir: Performing GET request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, NULL, 0, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: hpkv_readdir(%s): Failed to parse JSON response: %s\n", path, error.text);
            return -EIO;
        }
        keys_array = json_object_get(root, "keys");
        if (!json_is_array(keys_array)) {
            fprintf(stderr, "Error: hpkv_readdir(%s): API response missing 'keys' array.\n", path);
            json_decref(root);
            return -EIO;
        }

        size_t index;
        json_t *value;
        size_t prefix_len = strlen(prefix);

        json_array_foreach(keys_array, index, value) {
            if (!json_is_string(value)) continue;
            const char *key = json_string_value(value);
            DEBUG_LOG("hpkv_readdir: Processing key: %s\n", key);

            // Check if the key starts with the directory prefix
            if (strncmp(key, prefix, prefix_len) != 0) continue;

            // Extract the entry name relative to the current directory
            const char *entry_name_ptr = key + prefix_len;
            if (*entry_name_ptr == '\0') continue; // Skip the directory itself if listed

            // Find the next slash, if any
            const char *next_slash = strchr(entry_name_ptr, '/');

            // Check if it's a metadata key
            if (strstr(entry_name_ptr, ".__meta__") == (entry_name_ptr + strlen(entry_name_ptr) - 9)) {
                // It's a metadata key, extract the base name
                char base_name[512];
                size_t base_len = strlen(entry_name_ptr) - 9;
                if (base_len >= sizeof(base_name)) base_len = sizeof(base_name) - 1;
                strncpy(base_name, entry_name_ptr, base_len);
                base_name[base_len] = '\0';

                // Check if it represents a direct child (no slashes in base_name)
                if (strchr(base_name, '/') == NULL) {
                    // Skip adding empty entry for root metadata
                    if (strlen(base_name) > 0) {
                        DEBUG_LOG("hpkv_readdir: Adding entry: %s\n", base_name);
                        filler(buf, base_name, NULL, 0);
                    } else {
                        DEBUG_LOG("hpkv_readdir: Skipping empty entry name derived from root metadata.\n");
                    }
                } else {
                    // It's metadata for something deeper, extract the top-level dir name
                    const char *first_slash = strchr(base_name, '/');
                    if (first_slash) {
                        char top_dir[512];
                        size_t top_dir_len = first_slash - base_name;
                        if (top_dir_len < sizeof(top_dir)) {
                            strncpy(top_dir, base_name, top_dir_len);
                            top_dir[top_dir_len] = '\0';
                            // Check if this top-level dir was already added (simple check)
                            // A more robust solution might use a hash set
                            // For now, we might add duplicates if multiple items exist in a subdir
                            DEBUG_LOG("hpkv_readdir: Adding potential subdirectory entry: %s\n", top_dir);
                            filler(buf, top_dir, NULL, 0); // Add the directory name
                        }
                    }
                }
            } else if (strstr(entry_name_ptr, ".chunk") != NULL) {
                // It's a chunk key, ignore it directly in readdir
                DEBUG_LOG("hpkv_readdir: Skipping chunk key: %s\n", key);
                continue;
            } else if (next_slash) {
                 // It's a key for something inside a subdirectory, extract the subdir name
                 char subdir_name[512];
                 size_t subdir_len = next_slash - entry_name_ptr;
                 if (subdir_len < sizeof(subdir_name)) {
                     strncpy(subdir_name, entry_name_ptr, subdir_len);
                     subdir_name[subdir_len] = '\0';
                     // Add the subdirectory name (might add duplicates)
                     DEBUG_LOG("hpkv_readdir: Adding potential subdirectory entry from nested key: %s\n", subdir_name);
                     filler(buf, subdir_name, NULL, 0);
                 }
            } else {
                // It's likely a key for a file/object without metadata or chunks yet?
                // Or maybe an old key format. For now, let's ignore these unexpected keys.
                DEBUG_LOG("hpkv_readdir: Skipping unexpected key format: %s\n", key);
            }
        }
        json_decref(root);
    } else {
        if (response.memory) {
             free(response.memory);
             response.memory = NULL;
        }
        if (http_code == 404) {
            // If the directory prefix itself doesn't exist, it's not an error for readdir
            DEBUG_LOG("hpkv_readdir(%s): Prefix not found (404), directory is empty or doesn't exist.\n", path);
            ret = 0; // Treat as empty directory
        } else {
            fprintf(stderr, "Error: hpkv_readdir(%s): API GET failed, HTTP: %ld\n", path, http_code);
            ret = map_http_to_fuse_error(http_code);
        }
    }

    DEBUG_LOG("hpkv_readdir(%s): Finished with status %d\n", path, ret);
    return ret;
}

static int hpkv_mkdir(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_mkdir: Entered for path: %s, mode: %o\n", path, mode);
    int ret = 0;
    json_t *meta_json = NULL;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_mkdir(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    // Check if it already exists
    meta_json = get_metadata_json(path);
    if (meta_json) {
        json_decref(meta_json);
        DEBUG_LOG("hpkv_mkdir(%s): Path already exists.\n", path);
        return -EEXIST;
    }

    // Create new metadata JSON
    meta_json = json_object();
    if (!meta_json) {
        fprintf(stderr, "Error: hpkv_mkdir(%s): Failed to create JSON object.\n", path);
        return -ENOMEM;
    }

    time_t now = time(NULL);
    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | (mode & 0777))); // Ensure DIR type, apply requested mode
    json_object_set_new(meta_json, "uid", json_integer(context->uid));
    json_object_set_new(meta_json, "gid", json_integer(context->gid));
    json_object_set_new(meta_json, "size", json_integer(0));
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));
    json_object_set_new(meta_json, "num_chunks", json_integer(0));
    json_object_set_new(meta_json, "chunk_size", json_integer(HPKV_CHUNK_SIZE));

    ret = post_metadata_json(path, meta_json);
    json_decref(meta_json);

    if (ret == 0) {
        DEBUG_LOG("hpkv_mkdir(%s): Successfully created directory.\n", path);
    } else {
        fprintf(stderr, "Error: hpkv_mkdir(%s): Failed to post metadata (Error %d).\n", path, ret);
    }
    return ret;
}

static int hpkv_rmdir(const char *path) {
    DEBUG_LOG("hpkv_rmdir: Entered for path: %s\n", path);
    int ret = 0;
    char meta_key[1024];

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_rmdir(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    // Basic check: prevent removing root
    if (strcmp(path, "/") == 0) {
        return -EPERM; // Operation not permitted
    }

    // TODO: Add check for directory emptiness. This requires listing keys with prefix path + "/"
    // If any keys exist, return -ENOTEMPTY.
    // For now, we just attempt to delete the metadata.

    get_meta_key(path, meta_key, sizeof(meta_key));
    ret = delete_hpkv_key(meta_key);

    if (ret == 0) {
        DEBUG_LOG("hpkv_rmdir(%s): Successfully deleted directory metadata.\n", path);
    } else {
        fprintf(stderr, "Error: hpkv_rmdir(%s): Failed to delete metadata (Error %d).\n", path, ret);
    }
    return ret;
}

static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi; // Unused parameter
    DEBUG_LOG("hpkv_create: Entered for path: %s, mode: %o\n", path, mode);
    int ret = 0;
    json_t *meta_json = NULL;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_create(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    // Check if it already exists
    meta_json = get_metadata_json(path);
    if (meta_json) {
        json_decref(meta_json);
        DEBUG_LOG("hpkv_create(%s): Path already exists.\n", path);
        return -EEXIST;
    }

    // Create new metadata JSON for an empty file
    meta_json = json_object();
    if (!meta_json) {
        fprintf(stderr, "Error: hpkv_create(%s): Failed to create JSON object.\n", path);
        return -ENOMEM;
    }

    time_t now = time(NULL);
    json_object_set_new(meta_json, "mode", json_integer(S_IFREG | (mode & 0777))); // Ensure REG type, apply requested mode
    json_object_set_new(meta_json, "uid", json_integer(context->uid));
    json_object_set_new(meta_json, "gid", json_integer(context->gid));
    json_object_set_new(meta_json, "size", json_integer(0)); // New file, 0 size
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));
    json_object_set_new(meta_json, "num_chunks", json_integer(0)); // No chunks yet
    json_object_set_new(meta_json, "chunk_size", json_integer(HPKV_CHUNK_SIZE));

    ret = post_metadata_json(path, meta_json);
    json_decref(meta_json);

    if (ret == 0) {
        DEBUG_LOG("hpkv_create(%s): Successfully created file metadata.\n", path);
    } else {
        fprintf(stderr, "Error: hpkv_create(%s): Failed to post metadata (Error %d).\n", path, ret);
    }
    return ret;
}

static int hpkv_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_open: Entered for path: %s, flags: 0x%x\n", path, fi->flags);
    int ret = 0;
    json_t *meta_json = NULL;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_open(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    // Check if file exists
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_open(%s): File not found.\n", path);
        return -ENOENT;
    }

    // Handle O_TRUNC flag: If file is opened for writing and O_TRUNC is set, truncate it.
    if ((fi->flags & O_WRONLY || fi->flags & O_RDWR) && (fi->flags & O_TRUNC)) {
        DEBUG_LOG("hpkv_open(%s): O_TRUNC flag set, truncating file to 0.\n", path);
        json_object_set(meta_json, "size", json_integer(0));
        json_object_set(meta_json, "num_chunks", json_integer(0));
        // Update mtime and ctime
        time_t now = time(NULL);
        json_object_set(meta_json, "mtime", json_integer(now));
        json_object_set(meta_json, "ctime", json_integer(now));

        ret = post_metadata_json(path, meta_json);
        if (ret != 0) {
            fprintf(stderr, "Error: hpkv_open(%s): Failed to post metadata after O_TRUNC (Error %d).\n", path, ret);
            json_decref(meta_json);
            return ret;
        }
        // TODO: Delete existing chunk keys? Truncate handles this, maybe redundant here.
        // For simplicity, let truncate handle chunk deletion later if needed.
    }

    json_decref(meta_json);
    DEBUG_LOG("hpkv_open(%s): Open successful.\n", path);
    return 0; // Success
}

static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void) fi; // Unused parameter
    DEBUG_LOG("hpkv_read: Entered for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    int ret = 0;
    json_t *meta_json = NULL;
    off_t file_size = 0;
    int num_chunks = 0;
    size_t bytes_read = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_read(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_read(%s): Metadata not found.\n", path);
        return -ENOENT;
    }

    file_size = (off_t)json_integer_value(json_object_get(meta_json, "size"));
    num_chunks = (int)json_integer_value(json_object_get(meta_json, "num_chunks"));
    json_decref(meta_json); // Done with metadata for now

    if (offset >= file_size) {
        DEBUG_LOG("hpkv_read(%s): Offset (%ld) is beyond file size (%ld).\n", path, offset, file_size);
        return 0; // Read past end of file
    }

    // Adjust size if it goes beyond EOF
    if (offset + (off_t)size > file_size) {
        size = (size_t)(file_size - offset);
        DEBUG_LOG("hpkv_read(%s): Adjusted size to %zu to avoid reading past EOF.\n", path, size);
    }

    int start_chunk = offset / HPKV_CHUNK_SIZE;
    int end_chunk = (offset + size - 1) / HPKV_CHUNK_SIZE;
    if (end_chunk < 0) end_chunk = 0; // Handle size=0 case

    DEBUG_LOG("hpkv_read(%s): Reading from chunk %d to %d.\n", path, start_chunk, end_chunk);

    for (int i = start_chunk; i <= end_chunk; ++i) {
        struct MemoryStruct chunk_data = get_chunk_content(path, i);
        if (!chunk_data.memory) {
            fprintf(stderr, "Error: hpkv_read(%s): Failed to get content for chunk %d.\n", path, i);
            // Treat missing chunk as error? Or zero-filled? Let's return error for now.
            return -EIO;
        }

        off_t chunk_start_offset = (off_t)i * HPKV_CHUNK_SIZE;
        off_t read_start_in_chunk = 0;
        size_t read_len_in_chunk = chunk_data.size;

        // Calculate the starting position within this chunk
        if (offset > chunk_start_offset) {
            read_start_in_chunk = offset - chunk_start_offset;
        }

        // Calculate how much to read from this chunk
        if (read_start_in_chunk >= chunk_data.size) {
            // Offset starts after this chunk ends, should not happen with correct loop bounds
            free(chunk_data.memory);
            continue;
        }
        read_len_in_chunk = chunk_data.size - read_start_in_chunk;

        // Don't read more than requested total size
        if (bytes_read + read_len_in_chunk > size) {
            read_len_in_chunk = size - bytes_read;
        }

        DEBUG_LOG("hpkv_read(%s): Reading %zu bytes from chunk %d (offset %ld in chunk).\n", 
                  path, read_len_in_chunk, i, read_start_in_chunk);

        if (read_len_in_chunk > 0) {
            memcpy(buf + bytes_read, chunk_data.memory + read_start_in_chunk, read_len_in_chunk);
            bytes_read += read_len_in_chunk;
        }

        free(chunk_data.memory);

        if (bytes_read >= size) {
            break; // We have read enough
        }
    }

    DEBUG_LOG("hpkv_read(%s): Total bytes read: %zu\n", path, bytes_read);
    return (int)bytes_read; // Return number of bytes read
}

static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void) fi; // Unused parameter
    DEBUG_LOG("hpkv_write: Entered for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    int ret = 0;
    json_t *meta_json = NULL;
    off_t original_file_size = 0;
    int original_num_chunks = 0;
    size_t bytes_written = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_write(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_write(%s): Metadata not found.\n", path);
        return -ENOENT;
    }

    original_file_size = (off_t)json_integer_value(json_object_get(meta_json, "size"));
    original_num_chunks = (int)json_integer_value(json_object_get(meta_json, "num_chunks"));

    int start_chunk = offset / HPKV_CHUNK_SIZE;
    int end_chunk = (offset + size - 1) / HPKV_CHUNK_SIZE;
    if (end_chunk < 0) end_chunk = 0; // Handle size=0 case

    DEBUG_LOG("hpkv_write(%s): Writing from chunk %d to %d.\n", path, start_chunk, end_chunk);

    for (int i = start_chunk; i <= end_chunk; ++i) {
        off_t chunk_start_offset = (off_t)i * HPKV_CHUNK_SIZE;
        off_t write_start_in_chunk = 0;
        size_t write_len_in_chunk = 0;
        size_t current_chunk_content_size = 0;
        char *current_chunk_content = NULL;
        struct MemoryStruct chunk_data = {NULL, 0};

        // Calculate the starting position for writing within this chunk
        if (offset > chunk_start_offset) {
            write_start_in_chunk = offset - chunk_start_offset;
        }

        // Calculate how much data from the input buffer goes into this chunk
        size_t remaining_size_in_buffer = size - bytes_written;
        size_t space_left_in_chunk = HPKV_CHUNK_SIZE - write_start_in_chunk;
        write_len_in_chunk = (remaining_size_in_buffer < space_left_in_chunk) ? remaining_size_in_buffer : space_left_in_chunk;

        if (write_len_in_chunk == 0 && (offset + (off_t)size) > chunk_start_offset) {
             // This can happen if the write ends exactly at a chunk boundary
             // or if size is 0. No need to process this chunk further unless extending.
             if (offset + (off_t)size > original_file_size && i >= original_num_chunks) {
                 // Need to potentially create an empty chunk if extending file size
                 DEBUG_LOG("hpkv_write(%s): Write ends at boundary or size 0, potentially creating empty chunk %d.\n", path, i);
             } else {
                 continue;
             }
        }

        // Determine the required size of the chunk after writing
        size_t new_chunk_size = write_start_in_chunk + write_len_in_chunk;

        // Do we need to read the existing chunk content?
        // Yes, if the write doesn't start at the beginning of the chunk OR
        // if the write doesn't completely overwrite the chunk up to its previous size (if it existed).
        int need_read = 0;
        if (write_start_in_chunk > 0) {
            need_read = 1;
        } else if (i < original_num_chunks) {
            // Check if we need the tail end of the existing chunk
            off_t chunk_original_end = chunk_start_offset + HPKV_CHUNK_SIZE; // Theoretical end
            if (i == original_num_chunks - 1) { // Last original chunk
                chunk_original_end = original_file_size;
            }
            off_t write_end_in_chunk_abs = offset + bytes_written + write_len_in_chunk;
            if (write_end_in_chunk_abs < chunk_original_end) {
                 need_read = 1;
            }
        }

        if (need_read) {
            DEBUG_LOG("hpkv_write(%s): Need to read existing content for chunk %d.\n", path, i);
            chunk_data = get_chunk_content(path, i);
            if (chunk_data.memory) {
                current_chunk_content = chunk_data.memory;
                current_chunk_content_size = chunk_data.size;
                // Ensure the buffer is large enough for the write
                if (new_chunk_size > current_chunk_content_size) {
                    char *new_ptr = realloc(current_chunk_content, new_chunk_size);
                    if (!new_ptr) {
                        fprintf(stderr, "Error: hpkv_write(%s): Failed to realloc chunk buffer for chunk %d.\n", path, i);
                        if (current_chunk_content) free(current_chunk_content);
                        ret = -ENOMEM;
                        goto write_cleanup;
                    }
                    current_chunk_content = new_ptr;
                    // Zero out the potentially extended part if write doesn't cover it
                    if (write_start_in_chunk > current_chunk_content_size) {
                         memset(current_chunk_content + current_chunk_content_size, 0, write_start_in_chunk - current_chunk_content_size);
                    }
                }
            } else {
                // Chunk didn't exist or failed to read, create a new buffer
                current_chunk_content = calloc(1, new_chunk_size);
                if (!current_chunk_content) {
                    fprintf(stderr, "Error: hpkv_write(%s): Failed to calloc chunk buffer for chunk %d.\n", path, i);
                    ret = -ENOMEM;
                    goto write_cleanup;
                }
                current_chunk_content_size = 0; // Treat as empty initially
            }
        } else {
            // No need to read, create a new buffer just for the written data
            current_chunk_content = malloc(new_chunk_size);
            if (!current_chunk_content) {
                fprintf(stderr, "Error: hpkv_write(%s): Failed to malloc chunk buffer for chunk %d.\n", path, i);
                ret = -ENOMEM;
                goto write_cleanup;
            }
            current_chunk_content_size = 0; // Will be overwritten
        }

        // Perform the write into the chunk buffer
        if (write_len_in_chunk > 0) {
             DEBUG_LOG("hpkv_write(%s): Writing %zu bytes to chunk %d buffer at offset %ld.\n", 
                       path, write_len_in_chunk, i, write_start_in_chunk);
             memcpy(current_chunk_content + write_start_in_chunk, buf + bytes_written, write_len_in_chunk);
        }

        // Post the potentially modified chunk back to HPKV
        DEBUG_LOG("hpkv_write(%s): Posting chunk %d (new size %zu).\n", path, i, new_chunk_size);
        ret = post_chunk_content(path, i, current_chunk_content, new_chunk_size);
        free(current_chunk_content);
        current_chunk_content = NULL;

        if (ret != 0) {
            fprintf(stderr, "Error: hpkv_write(%s): Failed to post content for chunk %d (Error %d).\n", path, i, ret);
            goto write_cleanup;
        }

        bytes_written += write_len_in_chunk;
    }

    // Update metadata (size, num_chunks, mtime, ctime)
    off_t new_file_size = offset + size;
    if (new_file_size < original_file_size) {
        new_file_size = original_file_size; // Write doesn't shrink file, use truncate for that
    }
    int new_num_chunks = (new_file_size + HPKV_CHUNK_SIZE - 1) / HPKV_CHUNK_SIZE;
    if (new_file_size == 0) new_num_chunks = 0;

    DEBUG_LOG("hpkv_write(%s): Updating metadata. Original size=%ld, New potential size=%ld. Original chunks=%d, New chunks=%d.\n", 
              path, original_file_size, new_file_size, original_num_chunks, new_num_chunks);

    json_object_set(meta_json, "size", json_integer(new_file_size));
    json_object_set(meta_json, "num_chunks", json_integer(new_num_chunks));
    time_t now = time(NULL);
    json_object_set(meta_json, "mtime", json_integer(now));
    json_object_set(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_write(%s): Failed to post updated metadata (Error %d).\n", path, ret);
    } else {
        DEBUG_LOG("hpkv_write(%s): Successfully wrote %zu bytes.\n", path, bytes_written);
        ret = (int)bytes_written; // Return number of bytes written on success
    }

write_cleanup:
    if (meta_json) json_decref(meta_json);
    return ret;
}

static int hpkv_truncate(const char *path, off_t size) {
    DEBUG_LOG("hpkv_truncate: Entered for path: %s, size: %ld\n", path, size);
    int ret = 0;
    json_t *meta_json = NULL;
    off_t original_file_size = 0;
    int original_num_chunks = 0;

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_truncate(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_truncate(%s): Metadata not found.\n", path);
        return -ENOENT;
    }

    original_file_size = (off_t)json_integer_value(json_object_get(meta_json, "size"));
    original_num_chunks = (int)json_integer_value(json_object_get(meta_json, "num_chunks"));

    if (size == original_file_size) {
        DEBUG_LOG("hpkv_truncate(%s): Size unchanged, nothing to do.\n", path);
        json_decref(meta_json);
        return 0; // No change needed
    }

    int new_num_chunks = (size + HPKV_CHUNK_SIZE - 1) / HPKV_CHUNK_SIZE;
    if (size == 0) new_num_chunks = 0;

    DEBUG_LOG("hpkv_truncate(%s): Original size=%ld, New size=%ld. Original chunks=%d, New chunks=%d.\n", 
              path, original_file_size, size, original_num_chunks, new_num_chunks);

    // Handle shrinking the file
    if (size < original_file_size) {
        // Delete excess chunks
        for (int i = new_num_chunks; i < original_num_chunks; ++i) {
            char chunk_key[1024];
            get_chunk_key(path, i, chunk_key, sizeof(chunk_key));
            DEBUG_LOG("hpkv_truncate(%s): Deleting chunk %d (%s).\n", path, i, chunk_key);
            // Ignore errors here? If delete fails, metadata update will still happen.
            delete_hpkv_key(chunk_key);
        }
        // Truncate the last remaining chunk if necessary
        if (new_num_chunks > 0) {
            int last_chunk_index = new_num_chunks - 1;
            off_t last_chunk_offset = (off_t)last_chunk_index * HPKV_CHUNK_SIZE;
            size_t size_in_last_chunk = size - last_chunk_offset;
            
            struct MemoryStruct chunk_data = get_chunk_content(path, last_chunk_index);
            if (chunk_data.memory && chunk_data.size > size_in_last_chunk) {
                DEBUG_LOG("hpkv_truncate(%s): Truncating content of last chunk %d to %zu bytes.\n", 
                          path, last_chunk_index, size_in_last_chunk);
                ret = post_chunk_content(path, last_chunk_index, chunk_data.memory, size_in_last_chunk);
                free(chunk_data.memory);
                if (ret != 0) {
                    fprintf(stderr, "Error: hpkv_truncate(%s): Failed to post truncated last chunk %d (Error %d).\n", 
                              path, last_chunk_index, ret);
                    goto truncate_cleanup; // Abort if we can't write the truncated chunk
                }
            } else if (chunk_data.memory) {
                 free(chunk_data.memory); // No truncation needed for this chunk's content
            } else {
                 // Last chunk doesn't exist? This might happen if extending then shrinking.
                 // Create an empty chunk of the correct size?
                 // For simplicity, let's assume if size > 0, the chunk should exist or be created.
                 // If size_in_last_chunk is 0, we don't need to do anything here.
                 if (size_in_last_chunk > 0) {
                     DEBUG_LOG("hpkv_truncate(%s): Last chunk %d missing, creating empty chunk of size %zu.\n", 
                               path, last_chunk_index, size_in_last_chunk);
                     char *empty_buf = calloc(1, size_in_last_chunk);
                     if (!empty_buf) { ret = -ENOMEM; goto truncate_cleanup; }
                     ret = post_chunk_content(path, last_chunk_index, empty_buf, size_in_last_chunk);
                     free(empty_buf);
                     if (ret != 0) {
                         fprintf(stderr, "Error: hpkv_truncate(%s): Failed to post new empty last chunk %d (Error %d).\n", 
                                   path, last_chunk_index, ret);
                         goto truncate_cleanup;
                     }
                 }
            }
        }
    }
    // Handle extending the file (handled implicitly by write, but truncate might extend beyond last write)
    else { // size > original_file_size
        // If extending, ensure the last chunk exists and has the correct (potentially partial) size.
        // Write operation usually handles extension, but truncate might be called independently.
        if (new_num_chunks > 0) {
            int last_chunk_index = new_num_chunks - 1;
            off_t last_chunk_offset = (off_t)last_chunk_index * HPKV_CHUNK_SIZE;
            size_t size_in_last_chunk = size - last_chunk_offset;
            size_t current_last_chunk_size = 0;
            struct MemoryStruct chunk_data = {NULL, 0};

            if (last_chunk_index < original_num_chunks) {
                 chunk_data = get_chunk_content(path, last_chunk_index);
                 if (chunk_data.memory) {
                     current_last_chunk_size = chunk_data.size;
                 }
            }

            if (current_last_chunk_size < size_in_last_chunk) {
                 DEBUG_LOG("hpkv_truncate(%s): Extending last chunk %d from %zu to %zu bytes.\n", 
                           path, last_chunk_index, current_last_chunk_size, size_in_last_chunk);
                 char *new_buf = calloc(1, size_in_last_chunk);
                 if (!new_buf) { ret = -ENOMEM; if (chunk_data.memory) free(chunk_data.memory); goto truncate_cleanup; }
                 if (chunk_data.memory) {
                     memcpy(new_buf, chunk_data.memory, current_last_chunk_size);
                     free(chunk_data.memory);
                 }
                 ret = post_chunk_content(path, last_chunk_index, new_buf, size_in_last_chunk);
                 free(new_buf);
                 if (ret != 0) {
                     fprintf(stderr, "Error: hpkv_truncate(%s): Failed to post extended last chunk %d (Error %d).\n", 
                               path, last_chunk_index, ret);
                     goto truncate_cleanup;
                 }
            } else if (chunk_data.memory) {
                 free(chunk_data.memory); // No extension needed for this chunk
            }
        }
    }

    // Update metadata (size, num_chunks, mtime, ctime)
    json_object_set(meta_json, "size", json_integer(size));
    json_object_set(meta_json, "num_chunks", json_integer(new_num_chunks));
    time_t now = time(NULL);
    json_object_set(meta_json, "mtime", json_integer(now));
    json_object_set(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_truncate(%s): Failed to post updated metadata (Error %d).\n", path, ret);
    } else {
        DEBUG_LOG("hpkv_truncate(%s): Successfully truncated file to size %ld.\n", path, size);
    }

truncate_cleanup:
    if (meta_json) json_decref(meta_json);
    return ret;
}

static int hpkv_unlink(const char *path) {
    DEBUG_LOG("hpkv_unlink: Entered for path: %s\n", path);
    int ret = 0;
    json_t *meta_json = NULL;
    int num_chunks = 0;
    char meta_key[1024];

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_unlink(%s): Invalid FUSE context!\n", path);
        return -EIO;
    }

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_unlink(%s): File not found.\n", path);
        return -ENOENT; // File doesn't exist
    }

    // Check if it's a directory (unlink shouldn't delete directories)
    mode_t mode = (mode_t)json_integer_value(json_object_get(meta_json, "mode"));
    if (S_ISDIR(mode)) {
        json_decref(meta_json);
        DEBUG_LOG("hpkv_unlink(%s): Attempted to unlink a directory.\n", path);
        return -EISDIR; // Is a directory
    }

    num_chunks = (int)json_integer_value(json_object_get(meta_json, "num_chunks"));
    json_decref(meta_json); // Done with metadata

    // Delete all chunks
    DEBUG_LOG("hpkv_unlink(%s): Deleting %d chunks.\n", path, num_chunks);
    for (int i = 0; i < num_chunks; ++i) {
        char chunk_key[1024];
        get_chunk_key(path, i, chunk_key, sizeof(chunk_key));
        // Ignore errors during chunk deletion? If metadata delete succeeds, file is effectively gone.
        delete_hpkv_key(chunk_key);
    }

    // Delete metadata key
    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("hpkv_unlink(%s): Deleting metadata key %s.\n", path, meta_key);
    ret = delete_hpkv_key(meta_key);

    if (ret == 0) {
        DEBUG_LOG("hpkv_unlink(%s): Successfully unlinked file.\n", path);
    } else {
        fprintf(stderr, "Error: hpkv_unlink(%s): Failed to delete metadata (Error %d).\n", path, ret);
    }
    return ret;
}

// NOTE: This rename is NOT ATOMIC.
// It involves copying metadata, copying all chunks, then deleting old metadata/chunks.
// An interruption could leave the filesystem in an inconsistent state.
static int hpkv_rename(const char *from, const char *to) {
    DEBUG_LOG("hpkv_rename: Entered from: %s, to: %s\n", from, to);
    int ret = 0;
    json_t *meta_json = NULL;
    int num_chunks = 0;
    char from_meta_key[1024], to_meta_key[1024];

    struct fuse_context *context = fuse_get_context();
    if (!context || !context->private_data) {
        fprintf(stderr, "Error: hpkv_rename(%s -> %s): Invalid FUSE context!\n", from, to);
        return -EIO;
    }

    // 1. Get metadata of the source
    meta_json = get_metadata_json(from);
    if (!meta_json) {
        DEBUG_LOG("hpkv_rename(%s -> %s): Source path not found.\n", from, to);
        return -ENOENT;
    }
    num_chunks = (int)json_integer_value(json_object_get(meta_json, "num_chunks"));

    // 2. Check if destination exists (rename should overwrite files, fail for dirs?)
    json_t *to_meta_json = get_metadata_json(to);
    if (to_meta_json) {
        mode_t to_mode = (mode_t)json_integer_value(json_object_get(to_meta_json, "mode"));
        mode_t from_mode = (mode_t)json_integer_value(json_object_get(meta_json, "mode"));
        json_decref(to_meta_json);

        if (S_ISDIR(to_mode)) {
            // Cannot overwrite a directory with a file/directory
            DEBUG_LOG("hpkv_rename(%s -> %s): Destination is a directory.\n", from, to);
            json_decref(meta_json);
            return -EISDIR;
        } else if (S_ISDIR(from_mode)) {
             // Cannot rename a directory over a file
             DEBUG_LOG("hpkv_rename(%s -> %s): Cannot rename directory over a file.\n", from, to);
             json_decref(meta_json);
             return -ENOTDIR;
        } else {
            // Overwriting a file, delete the destination first
            DEBUG_LOG("hpkv_rename(%s -> %s): Destination file exists, deleting it first.\n", from, to);
            ret = hpkv_unlink(to); // Use unlink to handle chunks
            if (ret != 0) {
                fprintf(stderr, "Error: hpkv_rename(%s -> %s): Failed to delete existing destination file (Error %d).\n", from, to, ret);
                json_decref(meta_json);
                return ret;
            }
        }
    }

    // 3. Post the metadata to the new path
    // Update ctime for the rename operation itself
    time_t now = time(NULL);
    json_object_set(meta_json, "ctime", json_integer(now));
    ret = post_metadata_json(to, meta_json);
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_rename(%s -> %s): Failed to post metadata to destination (Error %d).\n", from, to, ret);
        json_decref(meta_json);
        return ret;
    }

    // 4. Copy all chunks from source path to destination path
    DEBUG_LOG("hpkv_rename(%s -> %s): Copying %d chunks.\n", from, to, num_chunks);
    for (int i = 0; i < num_chunks; ++i) {
        struct MemoryStruct chunk_data = get_chunk_content(from, i);
        if (chunk_data.memory) {
            ret = post_chunk_content(to, i, chunk_data.memory, chunk_data.size);
            free(chunk_data.memory);
            if (ret != 0) {
                fprintf(stderr, "Error: hpkv_rename(%s -> %s): Failed to post chunk %d to destination (Error %d).\n", from, to, i, ret);
                // Attempt to clean up partially copied data?
                hpkv_unlink(to); // Try to delete the partially renamed file
                json_decref(meta_json);
                return ret;
            }
        } else {
            // Chunk missing from source? Log warning but continue?
            fprintf(stderr, "Warning: hpkv_rename(%s -> %s): Source chunk %d missing or failed to read.\n", from, to, i);
            // If we continue, the renamed file might be corrupted.
            // Let's abort here for safety.
            hpkv_unlink(to); // Try to delete the partially renamed file
            json_decref(meta_json);
            return -EIO;
        }
    }

    // 5. Delete the old metadata and chunks
    DEBUG_LOG("hpkv_rename(%s -> %s): Deleting original file/directory.\n", from, to);
    // Use unlink for files, rmdir for directories (based on original mode)
    mode_t from_mode = (mode_t)json_integer_value(json_object_get(meta_json, "mode"));
    if (S_ISDIR(from_mode)) {
         ret = hpkv_rmdir(from);
    } else {
         ret = hpkv_unlink(from);
    }
    // Ignore delete errors? If copy succeeded, rename is effectively done.
    if (ret != 0) {
         fprintf(stderr, "Warning: hpkv_rename(%s -> %s): Failed to delete original path (Error %d), but copy succeeded.\n", from, to, ret);
         ret = 0; // Report success as the 'to' path now exists
    }

    json_decref(meta_json);
    DEBUG_LOG("hpkv_rename(%s -> %s): Rename successful (non-atomic).\n", from, to);
    return ret;
}

// Helper function to update specific metadata fields
static int update_metadata_field(const char *path, const char *field_name, json_t *new_value) {
    int ret = 0;
    json_t *meta_json = get_metadata_json(path);
    if (!meta_json) {
        return -ENOENT;
    }

    // Update the specific field
    json_object_set(meta_json, field_name, new_value); // Note: Steals reference to new_value

    // Update ctime as metadata is changing
    time_t now = time(NULL);
    json_object_set_new(meta_json, "ctime", json_integer(now));
    // Optionally update mtime for chmod/chown?
    // json_object_set_new(meta_json, "mtime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    json_decref(meta_json);
    return ret;
}

static int hpkv_chmod(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_chmod: Entered for path: %s, mode: %o\n", path, mode);
    // We only care about the permission bits, not the file type bits
    return update_metadata_field(path, "mode", json_integer(mode & 0777));
}

static int hpkv_chown(const char *path, uid_t uid, gid_t gid) {
    DEBUG_LOG("hpkv_chown: Entered for path: %s, uid: %d, gid: %d\n", path, uid, gid);
    int ret = 0;
    json_t *meta_json = get_metadata_json(path);
    if (!meta_json) {
        return -ENOENT;
    }

    // Update uid and gid
    // Only update if value is not -1 (convention for "don't change")
    if (uid != (uid_t)-1) {
        json_object_set(meta_json, "uid", json_integer(uid));
    }
    if (gid != (gid_t)-1) {
        json_object_set(meta_json, "gid", json_integer(gid));
    }

    // Update ctime
    time_t now = time(NULL);
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    json_decref(meta_json);
    return ret;
}

static int hpkv_utimens(const char *path, const struct timespec ts[2]) {
    DEBUG_LOG("hpkv_utimens: Entered for path: %s\n", path);
    int ret = 0;
    json_t *meta_json = get_metadata_json(path);
    if (!meta_json) {
        return -ENOENT;
    }

    // Update atime and mtime from timespec array
    // ts[0] is access time, ts[1] is modification time
    json_object_set(meta_json, "atime", json_integer(ts[0].tv_sec));
    json_object_set(meta_json, "mtime", json_integer(ts[1].tv_sec));

    // Update ctime
    time_t now = time(NULL);
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    json_decref(meta_json);
    return ret;
}

// --- FUSE Operations Struct ---

static struct fuse_operations hpkv_oper = {
    .getattr    = hpkv_getattr,
    .readdir    = hpkv_readdir,
    .mkdir      = hpkv_mkdir,
    .rmdir      = hpkv_rmdir,
    .create     = hpkv_create,
    .open       = hpkv_open,
    .read       = hpkv_read,
    .write      = hpkv_write,
    .truncate   = hpkv_truncate,
    .unlink     = hpkv_unlink,
    .rename     = hpkv_rename,
    .chmod      = hpkv_chmod,
    .chown      = hpkv_chown,
    .utimens    = hpkv_utimens,
};

// --- Main Function & Option Parsing ---

#define HPKV_OPT_KEY(t, p, v) { t, offsetof(struct hpkv_options, p), v }

static struct fuse_opt hpkv_opts[] = {
    HPKV_OPT_KEY("--api-url=%s", api_base_url, 0),
    HPKV_OPT_KEY("--api-key=%s", api_key, 0),
    FUSE_OPT_END
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct hpkv_options options;
    int ret;

    // Initialize options
    memset(&options, 0, sizeof(options));

    // Parse command line options
    if (fuse_opt_parse(&args, &options, hpkv_opts, NULL) == -1) {
        fprintf(stderr, "Error: Failed to parse FUSE options\n");
        return 1;
    }

    // Check required options
    if (!options.api_base_url || !options.api_key) {
        fprintf(stderr, "Error: --api-url and --api-key are required.\n");
        fprintf(stderr, "Usage: %s <mountpoint> --api-url=<url> --api-key=<key> [FUSE options]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }

    // Store config globally for early init check
    global_hpkv_config.api_base_url = strdup(options.api_base_url);
    global_hpkv_config.api_key = strdup(options.api_key);
    if (!global_hpkv_config.api_base_url || !global_hpkv_config.api_key) {
         fprintf(stderr, "Error: Failed to duplicate API config strings.\n");
         if (global_hpkv_config.api_base_url) free(global_hpkv_config.api_base_url);
         if (global_hpkv_config.api_key) free(global_hpkv_config.api_key);
         fuse_opt_free_args(&args);
         return 1;
    }

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // --- Automatic Root Initialization Check ---
    fprintf(stdout, "Starting HPKV FUSE filesystem (hpkvfs v0.1.4 - auto-root).\n");
    fprintf(stdout, "  API URL: %s\n", global_hpkv_config.api_base_url);
    ret = ensure_root_metadata_exists();
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to ensure root directory metadata exists (Error %d). Aborting.\n", ret);
        curl_global_cleanup();
        free(global_hpkv_config.api_base_url);
        free(global_hpkv_config.api_key);
        fuse_opt_free_args(&args);
        return 1;
    }
    // --- End Automatic Root Initialization ---

    fprintf(stdout, "Mounting filesystem...\n");

    // Pass the config to FUSE's private_data
    ret = fuse_main(args.argc, args.argv, &hpkv_oper, &global_hpkv_config);

    // Cleanup
    curl_global_cleanup();
    free(global_hpkv_config.api_base_url);
    free(global_hpkv_config.api_key);
    fuse_opt_free_args(&args);

    return ret;
}

