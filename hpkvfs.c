/*******************************************************************************
 * HPKV FUSE Filesystem
 * 
 * Connects to an HPKV REST API to provide a filesystem interface.
 * Supports Linux (primary) and experimental macOS (macFUSE).
 * Windows support requires significant porting (Dokan/WinFsp).
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

// --- Debug Logging --- 
// Simple debug flag, could be made a command-line option later
#define HPKVFS_DEBUG 1

#ifdef HPKVFS_DEBUG
#define DEBUG_LOG(...) fprintf(stderr, "DEBUG: " __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

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
    const char *request_body, 
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
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "hpkvfs/0.1.1"); // Updated version
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connection timeout
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);      // 30 seconds total timeout
    // Consider adding CURLOPT_FOLLOWLOCATION, 1L if redirects are expected/needed

    // Set headers
    snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", HPKV_DATA->api_key);
    headers = curl_slist_append(headers, api_key_header);
    if (request_body) {
        DEBUG_LOG("perform_hpkv_request: Request Body=%s\n", request_body);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, request_body);
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
    const char *request_body, 
    struct MemoryStruct *response_chunk,
    int max_retries
) {
    long http_code = -1;
    int retries = 0;
    long delay_ms = 100; // Initial delay 100ms

    while (retries <= max_retries) {
        // Ensure response chunk is reset for each attempt if needed (perform_hpkv_request handles init)
        http_code = perform_hpkv_request(method, path_segment, request_body, response_chunk);
        
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

// --- Metadata Helper ---

// Construct the metadata key for a given path.
// Ensures buffer safety.
static void get_meta_key(const char *path, char *meta_key_buf, size_t buf_size) {
    if (strcmp(path, "/") == 0) {
        // Special case for root directory metadata
        snprintf(meta_key_buf, buf_size, "/.__meta__");
    } else {
        size_t path_len = strlen(path);
        // Remove trailing slash if present (and not just "/")
        if (path_len > 1 && path[path_len - 1] == '/') {
             path_len--;
        }
        // Append metadata suffix, ensuring buffer space
        snprintf(meta_key_buf, buf_size, "%.*s.__meta__", (int)path_len, path);
    }
}

// Helper to get metadata JSON object for a path.
// Returns a new json_t object (caller must decref) or NULL on error/not found.
static json_t* get_metadata_json(const char *path) {
    // ADDED DEBUG LOG AT ENTRY
    DEBUG_LOG("get_metadata_json: Entered for path: %s\n", path);

    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL;
    json_error_t error;

    DEBUG_LOG("get_metadata_json: Getting FUSE context...\n");
    struct fuse_context *context = fuse_get_context();
    if (!context) {
        fprintf(stderr, "Error: get_metadata_json: fuse_get_context() returned NULL!\n");
        return NULL;
    }
    if (!context->private_data) {
        fprintf(stderr, "Error: get_metadata_json: FUSE context private_data is NULL!\n");
        return NULL;
    }
    DEBUG_LOG("get_metadata_json: FUSE context OK.\n");

    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("get_metadata_json: Meta key: %s\n", meta_key);
    encoded_key = url_encode(meta_key);
    // Check url_encode result
    if (!encoded_key) { return NULL; } // url_encode already printed error
    if (encoded_key[0] == '\0') { 
        fprintf(stderr, "Error: get_metadata_json: URL encoding of meta key resulted in empty string.\n");
        free(encoded_key); 
        return NULL; 
    }
    
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("get_metadata_json: Performing GET request for %s\n", api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("get_metadata_json: API GET successful (200 OK). Parsing outer JSON.\n");
        root = json_loads(response.memory, 0, &error);
        free(response.memory); // Free response buffer regardless of JSON parsing result
        if (!root) {
            fprintf(stderr, "Error: get_metadata_json(%s): Failed to parse outer JSON response: %s\n", path, error.text);
            return NULL;
        }
        DEBUG_LOG("get_metadata_json(%s): Parsed outer JSON successfully.\n", path);

        json_t *value_json = json_object_get(root, "value");
        if (!value_json) {
            fprintf(stderr, "Error: get_metadata_json(%s): API response missing 'value' field.\n", path);
            json_decref(root);
            return NULL;
        }

        if (json_is_string(value_json)) {
            const char *value_str = json_string_value(value_json);
            DEBUG_LOG("get_metadata_json(%s): Found 'value' as string: \"%.100s%s\"\n", 
                      path, value_str, strlen(value_str) > 100 ? "..." : "");
            
            // Now parse the inner JSON string
            json_t *inner_meta_json = json_loads(value_str, 0, &error);
            if (!inner_meta_json) {
                fprintf(stderr, "Error: get_metadata_json(%s): Failed to parse inner JSON string from 'value': %s\n", path, error.text);
                json_decref(root); // Decref the outer object
                return NULL;
            }
            // Ensure the inner JSON is an object
            if (!json_is_object(inner_meta_json)) {
                 fprintf(stderr, "Error: get_metadata_json(%s): Inner metadata parsed from 'value' is not a JSON object.\n", path);
                 json_decref(inner_meta_json);
                 json_decref(root);
                 return NULL;
            }
            DEBUG_LOG("get_metadata_json(%s): Successfully parsed inner metadata JSON object from 'value'.\n", path);
            json_decref(root); // Decref the outer object, we don't need it anymore
            return inner_meta_json; // Return the actual metadata object
        } else {
            // Handle case where value is not a string (unexpected based on API doc/curl command)
            fprintf(stderr, "Error: get_metadata_json(%s): API response 'value' field is not a JSON string as expected for metadata.\n", path);
            json_decref(root);
            return NULL;
        }
    } else {
        // Free response buffer if it exists (e.g., on 404 with body)
        if (response.memory) free(response.memory);
        // Don't log ENOENT errors loudly here, let the caller handle it based on context.
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
    char meta_key[1024];
    char *meta_json_str = NULL; // String representation of the metadata object
    char *request_body_str = NULL; // String representation of the full request {key, value}
    json_t *request_body_json = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    DEBUG_LOG("post_metadata_json: Called for path: %s\n", path);

    if (!meta_json || !json_is_object(meta_json)) {
         fprintf(stderr, "Error: post_metadata_json: Invalid meta_json provided.\n");
         if (meta_json) json_decref(meta_json); // Decref if not NULL
         return -EINVAL; 
    }

    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("post_metadata_json: Meta key: %s\n", meta_key);

    // Dump the metadata object itself into a string
    meta_json_str = json_dumps(meta_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(meta_json); // Decref the original object now that we have the string

    if (!meta_json_str) {
        fprintf(stderr, "Error: post_metadata_json: Failed to dump inner metadata object to string for %s\n", meta_key);
        return -EIO;
    }
    DEBUG_LOG("post_metadata_json: Inner metadata string: %s\n", meta_json_str);

    // Create the request body structure: { "key": "<meta_key>", "value": "<meta_json_string>" }
    request_body_json = json_object();
    if (!request_body_json) { 
        free(meta_json_str);
        return -ENOMEM; 
    }
    json_object_set_new(request_body_json, "key", json_string(meta_key));
    // The value is the JSON string we just created
    json_object_set_new(request_body_json, "value", json_string(meta_json_str));
    free(meta_json_str); // Free the intermediate string, it's now owned by request_body_json

    // Dump the full request body to a string
    request_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json); // Decref the container object

    if (!request_body_str) {
        fprintf(stderr, "Error: post_metadata_json: Failed to dump full request JSON for %s\n", meta_key);
        return -EIO;
    }

    // Perform the POST request
    DEBUG_LOG("post_metadata_json: Performing POST request for %s\n", meta_key);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_body_str, &response, 3);
    free(request_body_str);
    if (response.memory) free(response.memory); // Free response buffer if any

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Warning: post_metadata_json: Failed POST for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code, ret);
    }
    DEBUG_LOG("post_metadata_json: Finished for %s, returning %d\n", path, ret);
    return ret;
}

// --- FUSE Operations ---

// getattr: Get file attributes
static int hpkv_getattr(const char *path, struct stat *stbuf) {
    // ADDED DEBUG LOG AT ENTRY
    DEBUG_LOG("hpkv_getattr: Entered for path: %s\n", path);

    json_t *meta_json = NULL, *j_val;
    int ret = 0;

    DEBUG_LOG("hpkv_getattr(%s): Getting FUSE context...\n", path);
    struct fuse_context *context = fuse_get_context();
    if (!context) {
        fprintf(stderr, "Error: hpkv_getattr(%s): fuse_get_context() returned NULL!\n", path);
        return -EIO;
    }
    if (!context->private_data) {
        fprintf(stderr, "Error: hpkv_getattr(%s): FUSE context private_data is NULL!\n", path);
        return -EIO;
    }
    DEBUG_LOG("hpkv_getattr(%s): FUSE context OK.\n", path);

    DEBUG_LOG("hpkv_getattr(%s): Zeroing stat buffer...\n", path);
    memset(stbuf, 0, sizeof(struct stat));
    DEBUG_LOG("hpkv_getattr(%s): Calling get_metadata_json...\n", path);
    meta_json = get_metadata_json(path);

    if (meta_json) {
        DEBUG_LOG("hpkv_getattr(%s): get_metadata_json returned successfully. Populating stat buffer.\n", path);
        // Set defaults (permissions, links, owner, times)
        stbuf->st_mode = S_IFREG | 0644; // Default to regular file, 644 perm
        stbuf->st_nlink = 1;
        stbuf->st_size = 0;
        #ifdef _WIN32
            // Windows doesn't have POSIX UID/GID. Set to 0 or placeholder.
            stbuf->st_uid = 0;
            stbuf->st_gid = 0;
        #else
            stbuf->st_uid = context->uid; // Use UID/GID from FUSE context
            stbuf->st_gid = context->gid;
        #endif
        time_t now = time(NULL);
        stbuf->st_atime = now; // Access time
        stbuf->st_mtime = now; // Modification time
        stbuf->st_ctime = now; // Status change time

        // Extract attributes from JSON metadata
        j_val = json_object_get(meta_json, "mode");
        if (json_is_integer(j_val)) stbuf->st_mode = (mode_t)json_integer_value(j_val);
        
        j_val = json_object_get(meta_json, "size");
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

        // Adjust link count for directories (POSIX standard)
        if (S_ISDIR(stbuf->st_mode)) {
            stbuf->st_nlink = 2; // Directories always have at least '.' and '..'
            // TODO: Could potentially count subdirs via range query for accurate nlink > 2, but expensive.
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

// readdir: Read directory contents
static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_readdir: Called for path: %s, offset: %ld\n", path, offset);
    (void) offset; // Not using offset for now, API doesn't support pagination easily
    (void) fi;     // Not using file info

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

    // Add '.' and '..'
    DEBUG_LOG("hpkv_readdir(%s): Adding '.' and '..'\n", path);
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // Construct start key for range query (e.g., "/dir/")
    if (strcmp(path, "/") == 0) {
        snprintf(start_key_buf, sizeof(start_key_buf), "/");
    } else {
        snprintf(start_key_buf, sizeof(start_key_buf), "%s/", path);
    }
    DEBUG_LOG("hpkv_readdir(%s): Start key prefix: %s\n", path, start_key_buf);

    // Construct end key for range query (e.g., "/dir/\xFF")
    // \xFF is the largest possible byte value, ensuring we get all keys starting with the prefix
    snprintf(end_key_buf, sizeof(end_key_buf), "%s\xFF", start_key_buf);
    DEBUG_LOG("hpkv_readdir(%s): End key prefix: %s\n", path, end_key_buf);

    // URL encode keys
    encoded_start = url_encode(start_key_buf);
    encoded_end = url_encode(end_key_buf);
    if (!encoded_start || !encoded_end || encoded_start[0] == '\0' || encoded_end[0] == '\0') {
        fprintf(stderr, "Error: hpkv_readdir(%s): Failed to URL encode start/end keys.\n", path);
        if (encoded_start) free(encoded_start);
        if (encoded_end) free(encoded_end);
        return -EIO;
    }

    // Construct API path for range query
    snprintf(api_path, sizeof(api_path), "/records?startKey=%s&endKey=%s", encoded_start, encoded_end);
    free(encoded_start);
    free(encoded_end);

    DEBUG_LOG("hpkv_readdir(%s): Performing GET request for range: %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("hpkv_readdir(%s): API GET successful (200 OK). Parsing JSON response.\n", path);
        root = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!root) {
            fprintf(stderr, "Error: hpkv_readdir(%s): Failed to parse JSON response: %s\n", path, error.text);
            return -EIO;
        }

        // Expecting an object like { "records": [ {"key": "..."}, ... ] }
        records = json_object_get(root, "records");
        if (!json_is_array(records)) {
            fprintf(stderr, "Error: hpkv_readdir(%s): JSON response missing 'records' array or not an array.\n", path);
            json_decref(root);
            return -EIO;
        }
        DEBUG_LOG("hpkv_readdir(%s): Found %zu records in response.\n", path, json_array_size(records));

        // Iterate through the records array
        for (i = 0; i < json_array_size(records); i++) {
            record = json_array_get(records, i);
            if (!json_is_object(record)) continue; // Skip if not an object

            json_t *key_json = json_object_get(record, "key");
            if (!json_is_string(key_json)) continue; // Skip if key is not a string

            const char *full_key = json_string_value(key_json);
            DEBUG_LOG("hpkv_readdir(%s): Processing key: %s\n", path, full_key);

            // Extract the entry name from the full key relative to the current path
            const char *entry_name = full_key + strlen(start_key_buf);
            if (*entry_name == '\0') continue; // Skip the directory key itself if present

            // Find the next slash in the entry name
            const char *next_slash = strchr(entry_name, '/');
            char current_entry[256]; // Buffer for the directory entry name

            if (next_slash) {
                // This key represents something inside a subdirectory
                // We only want the name of the immediate subdirectory
                size_t subdir_len = next_slash - entry_name;
                if (subdir_len < sizeof(current_entry)) {
                    strncpy(current_entry, entry_name, subdir_len);
                    current_entry[subdir_len] = '\0';
                    // Check if it ends with .__meta__ (indicating a directory)
                    if (strstr(full_key, ".__meta__") == (full_key + strlen(full_key) - 9)) {
                         DEBUG_LOG("hpkv_readdir(%s): Adding directory entry: %s\n", path, current_entry);
                         filler(buf, current_entry, NULL, 0); // Add directory entry
                    }
                    // Skip processing further keys within this subdirectory for this readdir call
                    // We only want immediate children
                } else {
                    fprintf(stderr, "Warning: hpkv_readdir(%s): Subdirectory name too long: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name);
                }
            } else {
                // This key represents a direct child (file or metadata)
                // If it's a metadata key, extract the base name
                if (strstr(entry_name, ".__meta__") == (entry_name + strlen(entry_name) - 9)) {
                    size_t base_len = strlen(entry_name) - 9;
                    if (base_len < sizeof(current_entry)) {
                        strncpy(current_entry, entry_name, base_len);
                        current_entry[base_len] = '\0';
                        // We already added directories based on metadata, so skip adding again
                        // DEBUG_LOG("hpkv_readdir(%s): Found metadata for: %s (skipped adding)\n", path, current_entry);
                    } else {
                         fprintf(stderr, "Warning: hpkv_readdir(%s): Base name too long from metadata: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name);
                    }
                } else {
                    // This is a file content key
                    if (strlen(entry_name) < sizeof(current_entry)) {
                        strcpy(current_entry, entry_name);
                        DEBUG_LOG("hpkv_readdir(%s): Adding file entry: %s\n", path, current_entry);
                        filler(buf, current_entry, NULL, 0); // Add file entry
                    } else {
                         fprintf(stderr, "Warning: hpkv_readdir(%s): File name too long: %.*s...\n", path, (int)sizeof(current_entry)-1, entry_name);
                    }
                }
            }
            // TODO: Need to handle potential duplicates if both file content and metadata keys are listed
            // and avoid adding the same entry twice. A simple approach might be to use a set/hashmap
            // in memory during this loop, but that adds complexity.
            // Current approach might list directories twice if their metadata key appears after
            // a file inside them in the API response order. Let's refine this logic.
        }

        json_decref(root);
    } else {
        // Free response buffer if it exists (e.g., on 404 with body)
        if (response.memory) free(response.memory);
        fprintf(stderr, "Warning: hpkv_readdir(%s): API GET failed for range, HTTP: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
        // If the directory itself doesn't exist (404 on getattr), readdir shouldn't be called.
        // If the range query fails for other reasons, return the error.
    }

    DEBUG_LOG("hpkv_readdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}


// mkdir: Create a directory
static int hpkv_mkdir(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_mkdir: Called for path: %s, mode: %o\n", path, mode);
    json_t *meta_json = NULL;
    int ret = 0;
    struct fuse_context *context = fuse_get_context();

    // Check if it already exists (optional, API might handle conflict)
    // meta_json = get_metadata_json(path);
    // if (meta_json) {
    //     json_decref(meta_json);
    //     DEBUG_LOG("hpkv_mkdir(%s): Path already exists.\n", path);
    //     return -EEXIST;
    // }

    // Create metadata JSON object for the new directory
    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | (mode & 0777))); // Ensure S_IFDIR is set
    json_object_set_new(meta_json, "uid", json_integer(context ? context->uid : getuid()));
    json_object_set_new(meta_json, "gid", json_integer(context ? context->gid : getgid()));
    json_object_set_new(meta_json, "size", json_integer(0)); // Directories have 0 size
    time_t now = time(NULL);
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    // POST the metadata to HPKV
    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);

    DEBUG_LOG("hpkv_mkdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// rmdir: Remove a directory
static int hpkv_rmdir(const char *path) {
    DEBUG_LOG("hpkv_rmdir: Called for path: %s\n", path);
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // TODO: Add check if directory is empty using readdir logic.
    // FUSE expects rmdir to fail with -ENOTEMPTY if not empty.
    // This requires a range query like in readdir.
    // For now, we just attempt to delete the metadata key.

    // Get metadata key
    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("hpkv_rmdir(%s): Meta key: %s\n", path, meta_key);

    // URL encode key
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: hpkv_rmdir(%s): Failed to URL encode meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }

    // Construct API path for DELETE
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("hpkv_rmdir(%s): Performing DELETE request for %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) free(response.memory); // Free response buffer if any

    ret = map_http_to_fuse_error(http_code);
    if (ret == -ENOENT) {
        DEBUG_LOG("hpkv_rmdir(%s): Metadata key not found, assuming directory doesn't exist.\n", path);
        // If metadata doesn't exist, the directory doesn't exist.
    } else if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_rmdir(%s): Failed DELETE for metadata %s, HTTP: %ld, FUSE: %d\n", path, meta_key, http_code, ret);
    }

    DEBUG_LOG("hpkv_rmdir: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// create: Create a new file
static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_create: Called for path: %s, mode: %o\n", path, mode);
    (void) fi; // Not using file info for create itself
    json_t *meta_json = NULL;
    int ret = 0;
    struct fuse_context *context = fuse_get_context();

    // Create metadata JSON object for the new file
    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFREG | (mode & 0777))); // Ensure S_IFREG is set
    json_object_set_new(meta_json, "uid", json_integer(context ? context->uid : getuid()));
    json_object_set_new(meta_json, "gid", json_integer(context ? context->gid : getgid()));
    json_object_set_new(meta_json, "size", json_integer(0)); // New files have 0 size
    time_t now = time(NULL);
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    // POST the metadata to HPKV
    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);

    if (ret == 0) {
        // Optionally, create an empty content key as well?
        // Some FUSE operations might expect the content key to exist even if empty.
        // Let's try creating it.
        char *encoded_path = url_encode(path);
        if (encoded_path && encoded_path[0] != '\0') {
            char api_path[2048];
            char request_body[1024];
            struct MemoryStruct response;
            long http_code;

            snprintf(api_path, sizeof(api_path), "/record");
            // Create JSON body: { "key": "<path>", "value": "" }
            snprintf(request_body, sizeof(request_body), "{\"key\": \"%s\", \"value\": \"\"}", path); // Assuming path doesn't need escaping inside JSON string
            
            DEBUG_LOG("hpkv_create(%s): Attempting to create empty content key.\n", path);
            http_code = perform_hpkv_request_with_retry("POST", api_path, request_body, &response, 3);
            if (response.memory) free(response.memory);
            
            if (http_code < 200 || http_code >= 300) {
                fprintf(stderr, "Warning: hpkv_create(%s): Failed to create empty content key, HTTP: %ld\n", path, http_code);
                // Don't fail the create operation if only content key creation failed, metadata succeeded.
            }
            free(encoded_path);
        } else {
             fprintf(stderr, "Warning: hpkv_create(%s): Failed to URL encode path for empty content key creation.\n", path);
             if (encoded_path) free(encoded_path);
        }
    }

    DEBUG_LOG("hpkv_create: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// open: Open a file
// We don't need to do much here as data is fetched on read/write.
// We just need to check if the file exists (via getattr).
static int hpkv_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_open: Called for path: %s, flags: 0x%x\n", path, fi->flags);
    int res;
    struct stat stbuf;

    // Check if file exists by calling getattr
    res = hpkv_getattr(path, &stbuf);
    if (res != 0) {
        DEBUG_LOG("hpkv_open(%s): getattr failed, returning %d\n", path, res);
        return res; // Return the error from getattr (e.g., -ENOENT)
    }

    // Check if it's a directory (cannot open directories with O_RDWR or O_WRONLY)
    if (S_ISDIR(stbuf.st_mode)) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            DEBUG_LOG("hpkv_open(%s): Attempted to open directory with write access.\n", path);
            return -EISDIR;
        }
    }

    // Basic access checks (can be enhanced)
    // FUSE usually handles permissions based on getattr result, but we can add checks.
    // Example: Check if write access is requested but file is read-only via metadata.
    // if ((fi->flags & O_ACCMODE) != O_RDONLY && !(stbuf.st_mode & S_IWUSR)) {
    //     return -EACCES;
    // }

    // If O_TRUNC is set, we should truncate the file here.
    if (fi->flags & O_TRUNC) {
        DEBUG_LOG("hpkv_open(%s): O_TRUNC flag set, calling truncate(0).\n", path);
        res = hpkv_truncate(path, 0);
        if (res != 0) {
            fprintf(stderr, "Warning: hpkv_open(%s): Failed to truncate on open: %d\n", path, res);
            // Don't fail the open, but log the warning.
        }
    }

    DEBUG_LOG("hpkv_open: Finished for path: %s, returning 0\n", path);
    return 0; // Success
}

// read: Read data from a file
static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_read: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi; // Not using file info

    char *encoded_path = NULL;
    char api_path[2048];
    struct MemoryStruct response;
    long http_code;
    int ret = 0;
    json_t *root = NULL, *value_json = NULL;
    json_error_t error;
    const char *file_content = NULL;
    size_t file_size = 0;

    // URL encode path (content key is the path itself)
    encoded_path = url_encode(path);
    if (!encoded_path || encoded_path[0] == '\0') {
        fprintf(stderr, "Error: hpkv_read(%s): Failed to URL encode path.\n", path);
        if (encoded_path) free(encoded_path);
        return -EIO;
    }

    // Construct API path for GET content
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_path);
    free(encoded_path);

    DEBUG_LOG("hpkv_read(%s): Performing GET request for content: %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("hpkv_read(%s): API GET successful (200 OK). Parsing JSON response.\n", path);
        root = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!root) {
            fprintf(stderr, "Error: hpkv_read(%s): Failed to parse JSON response: %s\n", path, error.text);
            return -EIO;
        }

        value_json = json_object_get(root, "value");
        if (!json_is_string(value_json)) {
            fprintf(stderr, "Error: hpkv_read(%s): JSON response 'value' field is not a string.\n", path);
            json_decref(root);
            return -EIO;
        }

        // Get content and its actual size (Jansson might handle null bytes)
        file_content = json_string_value(value_json);
        file_size = json_string_length(value_json); // Use length for binary safety
        DEBUG_LOG("hpkv_read(%s): Retrieved content size: %zu\n", path, file_size);

        // Check if offset is beyond file size
        if ((size_t)offset >= file_size) {
            DEBUG_LOG("hpkv_read(%s): Offset %ld is beyond file size %zu. Returning 0 bytes.\n", path, offset, file_size);
            ret = 0; // Read past EOF
        } else {
            // Calculate bytes to copy
            size_t bytes_to_copy = file_size - (size_t)offset;
            if (bytes_to_copy > size) {
                bytes_to_copy = size; // Limit to buffer size
            }
            DEBUG_LOG("hpkv_read(%s): Copying %zu bytes from offset %ld to buffer.\n", path, bytes_to_copy, offset);
            memcpy(buf, file_content + offset, bytes_to_copy);
            ret = bytes_to_copy; // Return number of bytes read
        }

        json_decref(root);
    } else {
        // Free response buffer if it exists
        if (response.memory) free(response.memory);
        fprintf(stderr, "Warning: hpkv_read(%s): API GET failed for content, HTTP: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
        if (ret == -ENOENT) {
             DEBUG_LOG("hpkv_read(%s): Content key not found. Returning 0 bytes (or error?).\n", path);
             // If metadata exists but content doesn't, maybe return 0 bytes read?
             // Or should we return EIO? Let's return 0 for now.
             ret = 0; 
        } else if (ret == 0) {
             // If map_http_to_fuse_error returned 0 for a non-200 code (e.g., 204 No Content?)
             // Treat as empty file or error? Let's return 0 bytes read.
             DEBUG_LOG("hpkv_read(%s): API GET returned non-200 (%ld) but mapped to 0 error. Returning 0 bytes.\n", path, http_code);
             ret = 0;
        }
    }

    DEBUG_LOG("hpkv_read: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// write: Write data to a file
// Note: This implementation reads the entire existing content, modifies it in memory,
// and writes the whole thing back. This is INEFFICIENT for large files.
// A better approach would involve partial updates if the API supports it, or
// potentially using a temporary local file.
static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_write: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi; // Not using file info

    char *encoded_path = NULL;
    char api_path[2048];
    struct MemoryStruct response;
    long http_code;
    int ret = 0;
    json_t *root = NULL, *value_json = NULL, *meta_json = NULL;
    json_error_t error;
    char *old_content = NULL;
    size_t old_size = 0;
    char *new_content = NULL;
    size_t new_size = 0;
    char *request_body_str = NULL;
    json_t *request_body_json = NULL;

    // 1. Get current content (if any)
    encoded_path = url_encode(path);
    if (!encoded_path || encoded_path[0] == '\0') {
        fprintf(stderr, "Error: hpkv_write(%s): Failed to URL encode path.\n", path);
        if (encoded_path) free(encoded_path);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_path);
    free(encoded_path); // Free immediately after use

    DEBUG_LOG("hpkv_write(%s): Performing GET request for current content: %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("hpkv_write(%s): API GET successful (200 OK). Parsing JSON response.\n", path);
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: hpkv_write(%s): Failed to parse JSON response for current content: %s\n", path, error.text);
            return -EIO;
        }
        value_json = json_object_get(root, "value");
        if (json_is_string(value_json)) {
            // Need to copy the string content as json_decref will free it
            const char *temp_content = json_string_value(value_json);
            old_size = json_string_length(value_json);
            old_content = malloc(old_size + 1); // +1 for potential null terminator if needed
            if (!old_content) { json_decref(root); return -ENOMEM; }
            memcpy(old_content, temp_content, old_size);
            old_content[old_size] = '\0'; // Null-terminate just in case
            DEBUG_LOG("hpkv_write(%s): Retrieved current content size: %zu\n", path, old_size);
        } else {
            fprintf(stderr, "Warning: hpkv_write(%s): JSON response 'value' field is not a string. Assuming empty file.\n", path);
            // Treat as empty file if value isn't a string
            old_size = 0;
            old_content = NULL;
        }
        json_decref(root);
    } else if (http_code == 404) {
        DEBUG_LOG("hpkv_write(%s): Content key not found (404). Assuming new/empty file.\n", path);
        if (response.memory) free(response.memory); response.memory = NULL;
        old_size = 0;
        old_content = NULL;
    } else {
        fprintf(stderr, "Error: hpkv_write(%s): Failed to GET current content, HTTP: %ld\n", path, http_code);
        if (response.memory) free(response.memory); response.memory = NULL;
        return map_http_to_fuse_error(http_code);
    }

    // 2. Prepare new content in memory
    new_size = offset + size;
    if (new_size < old_size) {
        new_size = old_size; // Writing within existing size doesn't shrink file
    }
    DEBUG_LOG("hpkv_write(%s): Calculated new content size: %zu\n", path, new_size);

    new_content = malloc(new_size + 1); // +1 for null terminator if needed
    if (!new_content) {
        if (old_content) free(old_content);
        return -ENOMEM;
    }

    // Copy prefix from old content (if any)
    size_t pre_offset_size = (offset < (off_t)old_size) ? offset : old_size;
    if (old_content && pre_offset_size > 0) {
        memcpy(new_content, old_content, pre_offset_size);
    }
    // Zero out gap between pre_offset_size and offset if offset > old_size
    if ((size_t)offset > old_size) {
         memset(new_content + old_size, 0, (size_t)offset - old_size);
    }

    // Copy the new data being written
    memcpy(new_content + offset, buf, size);

    // Copy suffix from old content (if any)
    size_t suffix_start = offset + size;
    if (old_content && suffix_start < old_size) {
        memcpy(new_content + suffix_start, old_content + suffix_start, old_size - suffix_start);
    }
    new_content[new_size] = '\0'; // Null-terminate just in case

    if (old_content) free(old_content);

    // 3. POST the new content
    // Need to create JSON body: { "key": "<path>", "value": "<new_content_base64_or_escaped>" }
    // Using json_stringn for potential binary safety
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(path)); // Path is the key for content
    json_object_set_new(request_body_json, "value", json_stringn(new_content, new_size));
    free(new_content); // Content is now owned by json object

    request_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);

    if (!request_body_str) {
        fprintf(stderr, "Error: hpkv_write(%s): Failed to dump request JSON for new content.\n", path);
        return -EIO;
    }

    DEBUG_LOG("hpkv_write(%s): Performing POST request for new content (size %zu)\n", path, new_size);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_body_str, &response, 3);
    free(request_body_str);
    if (response.memory) free(response.memory); response.memory = NULL;

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_write(%s): Failed POST for new content, HTTP: %ld, FUSE: %d\n", path, http_code, ret);
        return ret;
    }

    // 4. Update metadata (size and mtime/ctime)
    DEBUG_LOG("hpkv_write(%s): Content POST successful. Updating metadata...\n", path);
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        // This shouldn't happen if create/open worked, but handle it.
        fprintf(stderr, "Warning: hpkv_write(%s): Failed to get metadata after writing content. Metadata might be inconsistent.\n", path);
        // Return success for the write itself, but log warning.
        return size; 
    }

    time_t now = time(NULL);
    json_object_set_new(meta_json, "size", json_integer(new_size));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);
    if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_write(%s): Failed to update metadata after writing content. Metadata might be inconsistent (FUSE error %d).\n", path, ret);
        // Return success for the write itself, but log warning.
    }

    DEBUG_LOG("hpkv_write: Finished for path: %s, returning written size %zu\n", path, size);
    return size; // Return number of bytes written on success
}

// truncate: Change the size of a file
static int hpkv_truncate(const char *path, off_t size) {
    DEBUG_LOG("hpkv_truncate: Called for path: %s, size: %ld\n", path, size);

    char *encoded_path = NULL;
    char api_path[2048];
    struct MemoryStruct response;
    long http_code;
    int ret = 0;
    json_t *root = NULL, *value_json = NULL, *meta_json = NULL;
    json_error_t error;
    char *old_content = NULL;
    size_t old_size = 0;
    char *new_content = NULL;
    size_t new_size = (size_t)size; // Target size
    char *request_body_str = NULL;
    json_t *request_body_json = NULL;

    if (size < 0) return -EINVAL; // Cannot truncate to negative size

    // 1. Get current content (if any)
    encoded_path = url_encode(path);
    if (!encoded_path || encoded_path[0] == '\0') {
        fprintf(stderr, "Error: hpkv_truncate(%s): Failed to URL encode path.\n", path);
        if (encoded_path) free(encoded_path);
        return -EIO;
    }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_path);
    free(encoded_path); // Free immediately after use

    DEBUG_LOG("hpkv_truncate(%s): Performing GET request for current content: %s\n", path, api_path);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (!root) {
            fprintf(stderr, "Error: hpkv_truncate(%s): Failed to parse JSON response for current content: %s\n", path, error.text);
            return -EIO;
        }
        value_json = json_object_get(root, "value");
        if (json_is_string(value_json)) {
            const char *temp_content = json_string_value(value_json);
            old_size = json_string_length(value_json);
            old_content = malloc(old_size + 1);
            if (!old_content) { json_decref(root); return -ENOMEM; }
            memcpy(old_content, temp_content, old_size);
            old_content[old_size] = '\0';
            DEBUG_LOG("hpkv_truncate(%s): Retrieved current content size: %zu\n", path, old_size);
        } else {
            old_size = 0;
            old_content = NULL;
        }
        json_decref(root);
    } else if (http_code == 404) {
        DEBUG_LOG("hpkv_truncate(%s): Content key not found (404). Assuming empty file.\n", path);
        if (response.memory) free(response.memory); response.memory = NULL;
        old_size = 0;
        old_content = NULL;
    } else {
        fprintf(stderr, "Error: hpkv_truncate(%s): Failed to GET current content, HTTP: %ld\n", path, http_code);
        if (response.memory) free(response.memory); response.memory = NULL;
        return map_http_to_fuse_error(http_code);
    }

    // If current size is already the target size, do nothing (but update metadata times)
    if (old_size == new_size) {
        DEBUG_LOG("hpkv_truncate(%s): File already has target size %zu. Updating metadata times only.\n", path, new_size);
        if (old_content) free(old_content);
        // Go straight to updating metadata
        goto update_metadata;
    }

    // 2. Prepare new content in memory
    DEBUG_LOG("hpkv_truncate(%s): Resizing content from %zu to %zu\n", path, old_size, new_size);
    new_content = malloc(new_size + 1);
    if (!new_content) {
        if (old_content) free(old_content);
        return -ENOMEM;
    }

    if (new_size > 0) {
        if (old_content) {
            size_t copy_size = (old_size < new_size) ? old_size : new_size;
            memcpy(new_content, old_content, copy_size);
            // If extending, zero-fill the new part
            if (new_size > old_size) {
                memset(new_content + old_size, 0, new_size - old_size);
            }
        } else {
            // If old content didn't exist but new size > 0, create zero-filled content
            memset(new_content, 0, new_size);
        }
    }
    new_content[new_size] = '\0'; // Null-terminate

    if (old_content) free(old_content);

    // 3. POST the new content
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(path));
    json_object_set_new(request_body_json, "value", json_stringn(new_content, new_size));
    free(new_content);

    request_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);

    if (!request_body_str) {
        fprintf(stderr, "Error: hpkv_truncate(%s): Failed to dump request JSON for new content.\n", path);
        return -EIO;
    }

    DEBUG_LOG("hpkv_truncate(%s): Performing POST request for new content (size %zu)\n", path, new_size);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_body_str, &response, 3);
    free(request_body_str);
    if (response.memory) free(response.memory); response.memory = NULL;

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_truncate(%s): Failed POST for new content, HTTP: %ld, FUSE: %d\n", path, http_code, ret);
        return ret;
    }

update_metadata:
    // 4. Update metadata (size and mtime/ctime)
    DEBUG_LOG("hpkv_truncate(%s): Content POST successful (or size matched). Updating metadata...\n", path);
    meta_json = get_metadata_json(path);
    if (!meta_json) {
        fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to get metadata after truncating content. Metadata might be inconsistent.\n", path);
        return 0; // Return success for truncate itself
    }

    time_t now = time(NULL);
    json_object_set_new(meta_json, "size", json_integer(new_size));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json);
    if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_truncate(%s): Failed to update metadata after truncating content (FUSE error %d).\n", path, ret);
        // Return success for truncate itself
    }

    DEBUG_LOG("hpkv_truncate: Finished for path: %s, returning %d\n", path, 0);
    return 0; // Return 0 on success
}

// unlink: Delete a file
static int hpkv_unlink(const char *path) {
    DEBUG_LOG("hpkv_unlink: Called for path: %s\n", path);
    char meta_key[1024];
    char api_path_meta[2048];
    char api_path_content[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response_meta, response_content;
    long http_code_meta, http_code_content;
    int ret_meta = 0, ret_content = 0;

    // 1. Delete the metadata key
    get_meta_key(path, meta_key, sizeof(meta_key));
    DEBUG_LOG("hpkv_unlink(%s): Meta key: %s\n", path, meta_key);
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: hpkv_unlink(%s): Failed to URL encode meta key.\n", path);
        if (encoded_key) free(encoded_key);
        return -EIO;
    }
    snprintf(api_path_meta, sizeof(api_path_meta), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("hpkv_unlink(%s): Performing DELETE request for metadata: %s\n", path, api_path_meta);
    http_code_meta = perform_hpkv_request_with_retry("DELETE", api_path_meta, NULL, &response_meta, 3);
    if (response_meta.memory) free(response_meta.memory);
    ret_meta = map_http_to_fuse_error(http_code_meta);
    if (ret_meta != 0 && ret_meta != -ENOENT) {
        fprintf(stderr, "Warning: hpkv_unlink(%s): Failed DELETE for metadata %s, HTTP: %ld, FUSE: %d\n", path, meta_key, http_code_meta, ret_meta);
        // Continue to delete content key anyway
    }

    // 2. Delete the content key
    encoded_key = url_encode(path);
    if (!encoded_key || encoded_key[0] == '\0') {
        fprintf(stderr, "Error: hpkv_unlink(%s): Failed to URL encode content key.\n", path);
        if (encoded_key) free(encoded_key);
        // Return error from metadata delete if it occurred, otherwise EIO
        return (ret_meta != 0 && ret_meta != -ENOENT) ? ret_meta : -EIO;
    }
    snprintf(api_path_content, sizeof(api_path_content), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("hpkv_unlink(%s): Performing DELETE request for content: %s\n", path, api_path_content);
    http_code_content = perform_hpkv_request_with_retry("DELETE", api_path_content, NULL, &response_content, 3);
    if (response_content.memory) free(response_content.memory);
    ret_content = map_http_to_fuse_error(http_code_content);
    if (ret_content != 0 && ret_content != -ENOENT) {
        fprintf(stderr, "Warning: hpkv_unlink(%s): Failed DELETE for content %s, HTTP: %ld, FUSE: %d\n", path, path, http_code_content, ret_content);
    }

    // Return success if either delete succeeded or returned ENOENT.
    // Return the first error encountered otherwise.
    if ((ret_meta == 0 || ret_meta == -ENOENT) && (ret_content == 0 || ret_content == -ENOENT)) {
        DEBUG_LOG("hpkv_unlink: Finished for path: %s, returning 0\n", path);
        return 0;
    } else if (ret_meta != 0 && ret_meta != -ENOENT) {
        DEBUG_LOG("hpkv_unlink: Finished for path: %s, returning meta error %d\n", path, ret_meta);
        return ret_meta;
    } else {
        DEBUG_LOG("hpkv_unlink: Finished for path: %s, returning content error %d\n", path, ret_content);
        return ret_content;
    }
}

// rename: Rename/move a file or directory
// Note: This is NOT atomic. It copies data/metadata then deletes old.
static int hpkv_rename(const char *from, const char *to) {
    DEBUG_LOG("hpkv_rename: Called from: %s, to: %s\n", from, to);
    struct stat stbuf;
    int ret = 0;

    // 1. Get attributes of the source to check if it exists and if it's a directory
    ret = hpkv_getattr(from, &stbuf);
    if (ret != 0) {
        DEBUG_LOG("hpkv_rename: Source path %s not found or error (%d).\n", from, ret);
        return ret; // Source doesn't exist
    }

    // 2. Check if destination exists (rename should typically overwrite files, fail for dirs)
    struct stat stbuf_to;
    int to_exists = (hpkv_getattr(to, &stbuf_to) == 0);
    if (to_exists) {
        DEBUG_LOG("hpkv_rename: Destination path %s exists.\n", to);
        if (S_ISDIR(stbuf.st_mode)) {
            // Cannot rename a directory to an existing path
            DEBUG_LOG("hpkv_rename: Cannot rename directory %s to existing path %s.\n", from, to);
            return -EEXIST; // Or -EISDIR? EEXIST seems more appropriate.
        } else if (S_ISDIR(stbuf_to.st_mode)) {
            // Cannot rename a file to an existing directory path
            DEBUG_LOG("hpkv_rename: Cannot rename file %s to existing directory %s.\n", from, to);
            return -EISDIR;
        } else {
            // Destination is a file, delete it first before renaming
            DEBUG_LOG("hpkv_rename: Destination file %s exists, attempting to delete it first.\n", to);
            ret = hpkv_unlink(to);
            if (ret != 0) {
                fprintf(stderr, "Error: hpkv_rename: Failed to delete existing destination file %s (%d).\n", to, ret);
                return ret;
            }
        }
    }

    // 3. Copy metadata from 'from' to 'to'
    DEBUG_LOG("hpkv_rename: Copying metadata from %s to %s\n", from, to);
    json_t *meta_json = get_metadata_json(from);
    if (!meta_json) {
        fprintf(stderr, "Error: hpkv_rename: Failed to get metadata for source %s after initial getattr succeeded!\n", from);
        return -EIO; // Should not happen if getattr succeeded
    }
    // Update ctime for the rename operation
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));
    ret = post_metadata_json(to, meta_json); // Takes ownership of meta_json
    if (ret != 0) {
        fprintf(stderr, "Error: hpkv_rename: Failed to post metadata for destination %s (%d).\n", to, ret);
        return ret;
    }

    // 4. If it's a file, copy content from 'from' to 'to'
    if (S_ISREG(stbuf.st_mode)) {
        DEBUG_LOG("hpkv_rename: Source %s is a file. Copying content to %s\n", from, to);
        char *encoded_from = url_encode(from);
        char api_path_from[2048];
        struct MemoryStruct response_get;
        long http_code_get;

        if (!encoded_from || encoded_from[0] == '\0') {
            fprintf(stderr, "Error: hpkv_rename: Failed to URL encode source path %s.\n", from);
            if (encoded_from) free(encoded_from);
            // Attempt to clean up destination metadata?
            hpkv_unlink(to); // Try to delete the newly created metadata for 'to'
            return -EIO;
        }
        snprintf(api_path_from, sizeof(api_path_from), "/record/%s", encoded_from);
        free(encoded_from);

        http_code_get = perform_hpkv_request_with_retry("GET", api_path_from, NULL, &response_get, 3);

        if (http_code_get == 200 && response_get.memory) {
            json_t *root_get = json_loads(response_get.memory, 0, NULL); // Ignore parse errors here?
            free(response_get.memory); response_get.memory = NULL;
            if (root_get) {
                json_t *value_json_get = json_object_get(root_get, "value");
                if (json_is_string(value_json_get)) {
                    const char *content_to_copy = json_string_value(value_json_get);
                    size_t content_size = json_string_length(value_json_get);

                    // POST this content to the 'to' path
                    json_t *post_body_json = json_object();
                    if (post_body_json) {
                        json_object_set_new(post_body_json, "key", json_string(to));
                        json_object_set_new(post_body_json, "value", json_stringn(content_to_copy, content_size));
                        char *post_body_str = json_dumps(post_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
                        json_decref(post_body_json);

                        if (post_body_str) {
                            struct MemoryStruct response_post;
                            long http_code_post;
                            DEBUG_LOG("hpkv_rename: Posting content (size %zu) to %s\n", content_size, to);
                            http_code_post = perform_hpkv_request_with_retry("POST", "/record", post_body_str, &response_post, 3);
                            free(post_body_str);
                            if (response_post.memory) free(response_post.memory);
                            ret = map_http_to_fuse_error(http_code_post);
                            if (ret != 0) {
                                fprintf(stderr, "Error: hpkv_rename: Failed to POST content to destination %s (%d).\n", to, ret);
                                json_decref(root_get);
                                hpkv_unlink(to); // Clean up destination
                                return ret;
                            }
                        } else {
                             fprintf(stderr, "Error: hpkv_rename: Failed to dump JSON for content POST to %s.\n", to);
                             ret = -EIO;
                        }
                    } else {
                        fprintf(stderr, "Error: hpkv_rename: Failed to create JSON object for content POST to %s.\n", to);
                        ret = -ENOMEM;
                    }
                } else {
                     fprintf(stderr, "Warning: hpkv_rename: Source content value for %s was not a string.\n", from);
                     // If source content wasn't string, maybe create empty content at dest?
                     ret = 0; // Treat as success for now?
                }
                json_decref(root_get);
                if (ret != 0) { hpkv_unlink(to); return ret; } // Abort on error
            } else {
                 fprintf(stderr, "Warning: hpkv_rename: Failed to parse JSON response when getting source content for %s.\n", from);
                 // Continue, assuming empty content?
            }
        } else if (http_code_get == 404) {
             DEBUG_LOG("hpkv_rename: Source content key %s not found (404). Renaming metadata only.\n", from);
             // If content key doesn't exist, that's fine, just rename metadata.
        } else {
            fprintf(stderr, "Error: hpkv_rename: Failed to GET source content %s (%ld).\n", from, http_code_get);
            if (response_get.memory) free(response_get.memory); response_get.memory = NULL;
            hpkv_unlink(to); // Clean up destination
            return map_http_to_fuse_error(http_code_get);
        }
    } else {
         DEBUG_LOG("hpkv_rename: Source %s is a directory. Renaming metadata only.\n", from);
         // For directories, we only need to move the metadata key.
    }

    // 5. Delete the old metadata and content (if file)
    DEBUG_LOG("hpkv_rename: Deleting original path %s\n", from);
    ret = hpkv_unlink(from); // unlink handles both metadata and content keys
    if (ret != 0) {
        fprintf(stderr, "Warning: hpkv_rename: Failed to delete original path %s after renaming (%d). Destination %s might be a duplicate.\n", from, ret, to);
        // Don't return error, rename technically succeeded, but log warning.
        ret = 0;
    }

    DEBUG_LOG("hpkv_rename: Finished from %s to %s, returning %d\n", from, to, ret);
    return ret;
}

// chmod: Change file permissions
static int hpkv_chmod(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_chmod: Called for path: %s, mode: %o\n", path, mode);
    json_t *meta_json = NULL;
    int ret = 0;

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_chmod(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    // Get current mode to preserve file type (S_IFREG/S_IFDIR)
    mode_t current_mode = 0;
    json_t *j_val = json_object_get(meta_json, "mode");
    if (json_is_integer(j_val)) {
        current_mode = (mode_t)json_integer_value(j_val);
    } else {
        // Should not happen if metadata exists, but default if missing
        current_mode = S_IFREG | 0644; 
    }

    // Update mode, preserving file type bits, applying new permission bits
    mode_t new_mode = (current_mode & S_IFMT) | (mode & ~S_IFMT);
    json_object_set_new(meta_json, "mode", json_integer(new_mode));
    // Update ctime
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);

    DEBUG_LOG("hpkv_chmod: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// chown: Change file owner/group
static int hpkv_chown(const char *path, uid_t uid, gid_t gid) {
    DEBUG_LOG("hpkv_chown: Called for path: %s, uid: %d, gid: %d\n", path, (int)uid, (int)gid);
    json_t *meta_json = NULL;
    int ret = 0;

    // Note: FUSE normally checks permissions before calling this.
    // If run as non-root, changing owner might fail unless specific conditions met.
    // Changing group might fail unless user is in the target group.
    // We simply update the metadata; actual enforcement is complex.

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_chown(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    // Update uid if changing (-1 means don't change)
    if (uid != (uid_t)-1) {
        json_object_set_new(meta_json, "uid", json_integer(uid));
    }
    // Update gid if changing (-1 means don't change)
    if (gid != (gid_t)-1) {
        json_object_set_new(meta_json, "gid", json_integer(gid));
    }
    // Update ctime
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);

    DEBUG_LOG("hpkv_chown: Finished for path: %s, returning %d\n", path, ret);
    return ret;
}

// utimens: Change file access/modification times
static int hpkv_utimens(const char *path, const struct timespec ts[2]) {
    DEBUG_LOG("hpkv_utimens: Called for path: %s\n", path);
    json_t *meta_json = NULL;
    int ret = 0;

    meta_json = get_metadata_json(path);
    if (!meta_json) {
        DEBUG_LOG("hpkv_utimens(%s): Metadata not found. Returning -ENOENT.\n", path);
        return -ENOENT;
    }

    // Update times if provided (tv_nsec == UTIME_OMIT means skip)
    if (ts[0].tv_nsec != UTIME_OMIT) {
        json_object_set_new(meta_json, "atime", json_integer(ts[0].tv_sec));
    }
    if (ts[1].tv_nsec != UTIME_OMIT) {
        json_object_set_new(meta_json, "mtime", json_integer(ts[1].tv_sec));
    }
    // Update ctime regardless
    json_object_set_new(meta_json, "ctime", json_integer(time(NULL)));

    // post_metadata_json takes ownership of meta_json
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
    (void) data; // Not used here, but could point to config struct
    (void) outargs; // Not used here
    (void) arg; // Avoid unused parameter warning

    switch (key) {
        // We let FUSE handle storing the string pointers in hpkv_options
        // based on the offsetof mapping defined in hpkv_opts.
        // Returning 0 means the option is recognized and handled by FUSE.
        case FUSE_OPT_KEY_OPT: // Non-matching option, pass to FUSE/mount
             return 1;
        case FUSE_OPT_KEY_NONOPT: // Non-option argument (mountpoint), pass to FUSE/mount
             return 1;
        default: // Our options (--api-url, --api-key) are handled by FUSE
             return 0;
    }
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct hpkv_options options = {0}; // Initialize options struct
    hpkv_config config = {0}; // Initialize config struct
    int ret;

    fprintf(stderr, "Starting HPKV FUSE filesystem (hpkvfs v0.1.1).\n");

    // Parse options
    if (fuse_opt_parse(&args, &options, hpkv_opts, hpkv_opt_proc) == -1) {
        fprintf(stderr, "Error: Failed to parse FUSE options.\n");
        return 1;
    }

    // Check required options
    if (!options.api_base_url || !options.api_key) {
        fprintf(stderr, "Error: --api-url and --api-key are required.\nUsage: %s <mountpoint> --api-url=<url> --api-key=<key> [FUSE options]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }

    // Copy options to persistent config (strdup needed as options pointers might be temporary)
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
    // Don't print API key to stderr

    // Initialize libcurl globally (recommended)
    curl_global_init(CURL_GLOBAL_DEFAULT);

    fprintf(stderr, "Mounting filesystem...\n");

    // Pass config struct as private_data to FUSE operations
    ret = fuse_main(args.argc, args.argv, &hpkv_oper, &config);

    fprintf(stderr, "Filesystem unmounted. Exiting with status %d.\n", ret);

    // Cleanup
    curl_global_cleanup();
    free(config.api_base_url);
    free(config.api_key);
    fuse_opt_free_args(&args);

    return ret;
}

