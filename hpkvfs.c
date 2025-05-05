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
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL;
    json_error_t error;

    DEBUG_LOG("get_metadata_json: Called for path: %s\n", path);

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
    json_decref(meta_json); // Decref the input object now, we have the string or NULL
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
    DEBUG_LOG("hpkv_getattr: Called for path: %s\n", path);
    json_t *meta_json = NULL, *j_val;
    int ret = 0;

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
            stbuf->st_uid = getuid(); // Default to current user/group
            stbuf->st_gid = getgid();
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
        DEBUG_LOG("hpkv_getattr(%s): Success. Mode=0%o, Size=%ld, UID=%d, GID=%d. Returning 0.\n", 
                  path, stbuf->st_mode, (long)stbuf->st_size, stbuf->st_uid, stbuf->st_gid);
    } else {
        DEBUG_LOG("hpkv_getattr(%s): get_metadata_json returned NULL. Returning -ENOENT.\n", path);
        ret = -ENOENT;
    }
    return ret;
}

// readdir: Read directory contents
static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_readdir: Called for path: %s, offset: %ld\n", path, offset);
    // Suppress unused parameter warnings if fi and offset are not used
    (void) fi;
    (void) offset; // Offset is typically ignored in simple FUSE implementations

    char api_path[2048];
    char start_key_buf[1024];
    char end_key_buf[1024];
    char *encoded_start_key = NULL;
    char *encoded_end_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *records = NULL, *record = NULL, *key_json = NULL;
    json_error_t error;
    int ret = 0;
    size_t i;
    size_t path_len = strlen(path);
    char *current_path_prefix = NULL;

    // Determine the prefix for the range query based on the directory path
    if (path_len == 1 && path[0] == '/') {
        current_path_prefix = strdup("/");
    } else {
        // Ensure path ends with '/' for prefix matching
        current_path_prefix = malloc(path_len + 2);
        if (current_path_prefix) {
            strcpy(current_path_prefix, path);
            if (path[path_len - 1] != '/') {
                current_path_prefix[path_len] = '/';
                current_path_prefix[path_len + 1] = '\0';
            }
        } 
    }
    if (!current_path_prefix) return -ENOMEM;
    size_t prefix_len = strlen(current_path_prefix);
    DEBUG_LOG("hpkv_readdir(%s): Prefix for range query: %s (len %zu)\n", path, current_path_prefix, prefix_len);

    // Prepare start and end keys for the API range query
    // startKey = prefix, endKey = prefix + high-byte character
    strncpy(start_key_buf, current_path_prefix, sizeof(start_key_buf) - 1);
    start_key_buf[sizeof(start_key_buf) - 1] = '\0';
    // Using 0xFF might be problematic with URL encoding or API interpretation.
    // A safer approach might be needed if keys can contain arbitrary bytes.
    // Let's try it for now.
    snprintf(end_key_buf, sizeof(end_key_buf), "%s\xFF", start_key_buf);

    encoded_start_key = url_encode(start_key_buf);
    encoded_end_key = url_encode(end_key_buf);
    if (!encoded_start_key || !encoded_end_key) { // Check for NULL from strdup failure
        fprintf(stderr, "Error: readdir: Failed to URL encode keys\n");
        free(encoded_start_key); free(encoded_end_key); free(current_path_prefix);
        return -EIO;
    }
    if (encoded_start_key[0] == '\0' || encoded_end_key[0] == '\0') { // Check for empty string from url_encode failure
        fprintf(stderr, "Error: readdir: URL encoding resulted in empty string\n");
        free(encoded_start_key); free(encoded_end_key); free(current_path_prefix);
        return -EIO;
    }

    // Construct API path for range query (limit results to avoid huge responses)
    snprintf(api_path, sizeof(api_path), "/records?startKey=%s&endKey=%s&limit=1000", 
             encoded_start_key, encoded_end_key);
    free(encoded_start_key); free(encoded_end_key);
    DEBUG_LOG("hpkv_readdir(%s): Performing GET request for range: %s\n", path, api_path);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("hpkv_readdir(%s): API GET successful (200 OK). Parsing response.\n", path);
        root = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!root) {
            fprintf(stderr, "Error: readdir: Failed to parse JSON response for %s: %s\n", path, error.text);
            free(current_path_prefix); return -EIO;
        }

        records = json_object_get(root, "records");
        if (!json_is_array(records)) {
            fprintf(stderr, "Error: readdir: API response for %s missing 'records' array\n", path);
            json_decref(root); free(current_path_prefix); return -EIO;
        }
        DEBUG_LOG("hpkv_readdir(%s): Found %zu records in range.\n", path, json_array_size(records));

        // Add standard '.' and '..' entries
        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);

        // TODO: Use a hash set to store unique entry names found to avoid duplicates 
        // if both content key (file) and meta key (file.__meta__) are returned by range query.

        // Process returned keys from the API
        for (i = 0; i < json_array_size(records); i++) {
            record = json_array_get(records, i);
            if (!json_is_object(record)) continue;
            key_json = json_object_get(record, "key");
            if (!json_is_string(key_json)) continue;

            const char *full_key = json_string_value(key_json);
            DEBUG_LOG("hpkv_readdir(%s): Processing key: %s\n", path, full_key);
            
            // Ensure the key actually starts with the prefix (API might be lenient)
            if (strncmp(full_key, current_path_prefix, prefix_len) != 0) {
                 DEBUG_LOG("hpkv_readdir(%s): Skipping key %s (doesn't match prefix %s)\n", path, full_key, current_path_prefix);
                 continue;
            }

            const char *name_start = full_key + prefix_len;
            if (name_start[0] == '\0') {
                 DEBUG_LOG("hpkv_readdir(%s): Skipping key %s (is prefix itself)\n", path, full_key);
                 continue; // Skip the prefix key itself (e.g., /dir/.__meta__ if path=/dir/)
            }

            // Find the first slash after the prefix to identify the entry name
            const char *first_slash = strchr(name_start, '/');
            char entry_name[256]; // Max filename length

            if (first_slash) {
                // This key represents something inside a subdirectory or a metadata key for a subdir.
                // We only want the immediate subdirectory name.
                // Check if it's the metadata key for a direct child directory.
                // Example: prefix=/a/, key=/a/b/.__meta__ -> entry_name="b"
                if (strncmp(first_slash, "/.__meta__", 10) == 0 && first_slash[10] == '\0') {
                    snprintf(entry_name, sizeof(entry_name), "%.*s", (int)(first_slash - name_start), name_start);
                    DEBUG_LOG("hpkv_readdir(%s): Found directory entry: %s (from meta key %s)\n", path, entry_name, full_key);
                    // TODO: Add to hash set first
                    filler(buf, entry_name, NULL, 0);
                }
                // Ignore deeper entries like /a/b/c or /a/b/c.__meta__ in this loop
                else {
                     DEBUG_LOG("hpkv_readdir(%s): Skipping key %s (deeper entry)\n", path, full_key);
                }
            } else {
                // No slash after prefix: This is potentially a file or its metadata key at the current level.
                // Example: prefix=/a/, key=/a/file or key=/a/file.__meta__
                const char *meta_suffix = ".__meta__";
                size_t name_len = strlen(name_start);
                size_t meta_suffix_len = strlen(meta_suffix);

                // Check if it ends with the metadata suffix
                if (name_len > meta_suffix_len && strcmp(name_start + name_len - meta_suffix_len, meta_suffix) == 0) {
                    // It's a metadata key: /a/file.__meta__ -> entry_name="file"
                    snprintf(entry_name, sizeof(entry_name), "%.*s", (int)(name_len - meta_suffix_len), name_start);
                    DEBUG_LOG("hpkv_readdir(%s): Found file entry: %s (from meta key %s)\n", path, entry_name, full_key);
                    // TODO: Add to hash set first
                    filler(buf, entry_name, NULL, 0);
                } else {
                    // It's likely a content key: /a/file -> entry_name="file"
                    snprintf(entry_name, sizeof(entry_name), "%s", name_start);
                    DEBUG_LOG("hpkv_readdir(%s): Found file entry: %s (from content key %s)\n", path, entry_name, full_key);
                    // TODO: Add to hash set first
                    filler(buf, entry_name, NULL, 0);
                }
            }
        }
        json_decref(root);
        ret = 0; // Success
    } else if (http_code == 404) {
        DEBUG_LOG("hpkv_readdir(%s): API GET for range returned 404. Checking if directory exists.\n", path);
        // API returned 404 for the range query - implies directory is empty (or doesn't exist)
        // Check if the directory metadata itself exists first?
        struct stat stbuf_check;
        if (hpkv_getattr(path, &stbuf_check) != 0) {
             DEBUG_LOG("hpkv_readdir(%s): getattr failed, directory likely doesn't exist. Returning -ENOENT.\n", path);
             ret = -ENOENT; // Directory itself doesn't exist
        } else if (!S_ISDIR(stbuf_check.st_mode)) {
             DEBUG_LOG("hpkv_readdir(%s): Path exists but is not a directory. Returning -ENOTDIR.\n", path);
             ret = -ENOTDIR; // Path exists but is not a directory
        } else {
            // Directory exists but range query returned 404 -> Empty directory
            DEBUG_LOG("hpkv_readdir(%s): Directory exists but is empty. Filling '.' and '..'.\n", path);
            filler(buf, ".", NULL, 0);
            filler(buf, "..", NULL, 0);
            ret = 0; 
        }
    } else {
        // Other API error during range query
        fprintf(stderr, "Error: readdir: API GET failed for %s range, HTTP: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    free(current_path_prefix);
    DEBUG_LOG("hpkv_readdir(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// mkdir: Create a directory
static int hpkv_mkdir(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_mkdir: Called for path: %s, mode: 0%o\n", path, mode);
    json_t *meta_json = NULL;
    int ret = 0;
    time_t now = time(NULL);

    // Check if path already exists
    struct stat stbuf;
    DEBUG_LOG("hpkv_mkdir(%s): Checking if path already exists...\n", path);
    if (hpkv_getattr(path, &stbuf) == 0) {
        DEBUG_LOG("hpkv_mkdir(%s): Path already exists. Returning -EEXIST.\n", path);
        return -EEXIST;
    }
    // If getattr failed with something other than ENOENT, return that error?
    // For now, assume failure means it doesn't exist.
    DEBUG_LOG("hpkv_mkdir(%s): Path does not exist. Proceeding with creation.\n", path);

    // Create metadata JSON object for the new directory
    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | mode)); // Set directory type and permissions
    #ifdef _WIN32
        json_object_set_new(meta_json, "uid", json_integer(0));
        json_object_set_new(meta_json, "gid", json_integer(0));
    #else
        json_object_set_new(meta_json, "uid", json_integer(getuid()));
        json_object_set_new(meta_json, "gid", json_integer(getgid()));
    #endif
    json_object_set_new(meta_json, "size", json_integer(0)); // Directories have 0 size in this model
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    // POST the metadata to HPKV
    // post_metadata_json takes ownership of meta_json
    DEBUG_LOG("hpkv_mkdir(%s): Posting metadata...\n", path);
    ret = post_metadata_json(path, meta_json);
    
    // meta_json is decref'd inside post_metadata_json regardless of success/failure
    DEBUG_LOG("hpkv_mkdir(%s): Finished, returning %d\n", path, ret);
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

    // --- Directory Emptiness Check --- 
    // TODO: Implement a robust check using readdir logic. 
    // This is crucial for POSIX compliance. Requires listing keys with the directory prefix.
    // If any keys exist other than the directory's own metadata key, return -ENOTEMPTY.
    // Skipping this check for now due to complexity.
    fprintf(stderr, "Warning: rmdir on %s: Emptiness check not implemented.\n", path);
    // return -EPERM; // Placeholder: Return error until check is implemented

    // Check if it's actually a directory first
    struct stat stbuf;
    DEBUG_LOG("hpkv_rmdir(%s): Checking if path is a directory...\n", path);
    ret = hpkv_getattr(path, &stbuf);
    if (ret != 0) {
        DEBUG_LOG("hpkv_rmdir(%s): getattr failed (%d). Returning error.\n", path, ret);
        return ret; // Doesn't exist or other error
    }
    if (!S_ISDIR(stbuf.st_mode)) {
        DEBUG_LOG("hpkv_rmdir(%s): Path is not a directory. Returning -ENOTDIR.\n", path);
        return -ENOTDIR; // Not a directory
    }
    DEBUG_LOG("hpkv_rmdir(%s): Path is a directory. Proceeding with deletion.\n", path);

    // Proceed to delete the metadata key
    get_meta_key(path, meta_key, sizeof(meta_key));
    encoded_key = url_encode(meta_key);
    if (!encoded_key) { return -EIO; }
    if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    DEBUG_LOG("hpkv_rmdir(%s): Performing DELETE request for meta key %s\n", path, meta_key);
    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) free(response.memory); // Free response buffer if any

    ret = map_http_to_fuse_error(http_code);
    // Ignore ENOENT if the key was already gone
    if (ret == -ENOENT) {
        DEBUG_LOG("hpkv_rmdir(%s): Meta key %s not found (ENOENT), treating as success.\n", path, meta_key);
        ret = 0;
    }

    if (ret != 0) {
         fprintf(stderr, "Warning: rmdir: API DELETE failed for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code, ret);
    }
    DEBUG_LOG("hpkv_rmdir(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// create: Create a new file
static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_create: Called for path: %s, mode: 0%o\n", path, mode);
    // Suppress unused parameter warning if fi is not used
    (void) fi;

    char content_key[1024];
    char *request_json_str = NULL;
    json_t *meta_json = NULL, *request_body_json = NULL;
    struct MemoryStruct response; 
    long http_code_content;
    int ret = 0;
    time_t now = time(NULL);

    // Check if path already exists
    struct stat stbuf;
    DEBUG_LOG("hpkv_create(%s): Checking if path already exists...\n", path);
    if (hpkv_getattr(path, &stbuf) == 0) {
        DEBUG_LOG("hpkv_create(%s): Path already exists. Returning -EEXIST.\n", path);
        return -EEXIST;
    }
    // If getattr failed with something other than ENOENT, return that error?
    DEBUG_LOG("hpkv_create(%s): Path does not exist. Proceeding with creation.\n", path);

    // 1. Create and POST metadata
    meta_json = json_object();
    if (!meta_json) return -ENOMEM;
    json_object_set_new(meta_json, "mode", json_integer(S_IFREG | mode)); // Regular file type
    #ifdef _WIN32
        json_object_set_new(meta_json, "uid", json_integer(0));
        json_object_set_new(meta_json, "gid", json_integer(0));
    #else
        json_object_set_new(meta_json, "uid", json_integer(getuid()));
        json_object_set_new(meta_json, "gid", json_integer(getgid()));
    #endif
    json_object_set_new(meta_json, "size", json_integer(0)); // New file has 0 size
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    DEBUG_LOG("hpkv_create(%s): Posting metadata...\n", path);
    ret = post_metadata_json(path, meta_json); // Takes ownership of meta_json
    if (ret != 0) {
        fprintf(stderr, "Error: create: Meta POST failed for %s, FUSE: %d\n", path, ret);
        // meta_json already decref'd by post_metadata_json
        return ret;
    }
    DEBUG_LOG("hpkv_create(%s): Metadata POST successful.\n", path);

    // 2. Create and POST empty content key
    // Use the path directly as the content key
    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    request_body_json = json_object();
    if (!request_body_json) { 
        /* TODO: Attempt to cleanup metadata? Difficult to do reliably. */ 
        return -ENOMEM; 
    }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    // Store empty content as an empty string value
    json_object_set_new(request_body_json, "value", json_string("")); 
    
    request_json_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    if (!request_json_str) { 
        fprintf(stderr, "Error: create: Failed to dump content JSON for %s\n", content_key);
        /* TODO: Cleanup metadata? */ 
        return -EIO; 
    }

    DEBUG_LOG("hpkv_create(%s): Posting empty content key %s...\n", path, content_key);
    http_code_content = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code_content);
    // If content POST failed (and wasn't EEXIST), log error and potentially try cleanup.
    if (ret != 0 && ret != -EEXIST) { 
        fprintf(stderr, "Error: create: Content POST failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code_content, ret);
        // TODO: Attempt to clean up the metadata key we created earlier.
        // char meta_key_cleanup[1024]; get_meta_key(path, meta_key_cleanup, sizeof(meta_key_cleanup)); ... DELETE ...
        return ret;
    }
    // If ret is EEXIST, it's okay, maybe created concurrently or existed before.
    DEBUG_LOG("hpkv_create(%s): Content POST successful or key already existed.\n", path);

    DEBUG_LOG("hpkv_create(%s): Finished successfully, returning 0\n", path);
    return 0; // Success
}

// open: Open a file
// FUSE checks permissions based on getattr mode before calling open.
// We just need to check if the file exists.
static int hpkv_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_open: Called for path: %s, flags: 0x%x\n", path, fi->flags);
    // Suppress unused parameter warning if fi is not used for specific flags
    // (void) fi;

    struct stat stbuf;
    int res = hpkv_getattr(path, &stbuf); // Check existence and get attributes
    if (res != 0) {
        DEBUG_LOG("hpkv_open(%s): getattr failed (%d). Returning error.\n", path, res);
        return res; // Return ENOENT or other error from getattr
    }
    
    // Check if it's a directory - cannot open directories like files
    if (S_ISDIR(stbuf.st_mode)) {
        DEBUG_LOG("hpkv_open(%s): Path is a directory. Returning -EISDIR.\n", path);
        return -EISDIR;
    }

    // TODO: Could potentially check fi->flags (O_RDONLY, O_WRONLY, O_RDWR) against file mode from getattr if needed.
    // FUSE usually handles basic permission checks based on getattr result.

    DEBUG_LOG("hpkv_open(%s): File exists. Returning 0.\n", path);
    return 0; // File exists, allow open
}

// read: Read data from an open file
static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_read: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    // Suppress unused parameter warning
    (void) fi;

    char content_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL;
    json_error_t error;
    int ret = 0;
    const char *file_content_ptr = NULL;
    size_t file_size = 0;
    size_t content_len_from_json = 0;

    // 1. Get authoritative size from metadata first
    DEBUG_LOG("hpkv_read(%s): Getting metadata for size check...\n", path);
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            file_size = (size_t)json_integer_value(j_size);
            DEBUG_LOG("hpkv_read(%s): Size from metadata: %zu\n", path, file_size);
        }
        // TODO: Optionally update atime here or after successful read?
        // time_t now = time(NULL); json_object_set_new(meta_json, "atime", json_integer(now)); post_metadata_json(path, meta_json); 
        json_decref(meta_json);
    } else {
        DEBUG_LOG("hpkv_read(%s): Failed to get metadata. Returning -ENOENT.\n", path);
        return -ENOENT; // Metadata must exist for a readable file
    }

    // Check for read past EOF based on metadata size
    if (offset >= (off_t)file_size) {
        DEBUG_LOG("hpkv_read(%s): Offset (%ld) >= file size (%zu). Returning 0 (EOF).\n", path, offset, file_size);
        return 0; // Reading at or beyond EOF returns 0 bytes
    }

    // 2. Get file content from content key
    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';
    encoded_key = url_encode(content_key);
    if (!encoded_key) { return -EIO; }
    if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    DEBUG_LOG("hpkv_read(%s): Performing GET request for content key %s\n", path, content_key);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        DEBUG_LOG("hpkv_read(%s): API GET successful (200 OK). Parsing response.\n", path);
        root = json_loads(response.memory, 0, &error);
        free(response.memory); // Free response buffer
        if (!root) {
            fprintf(stderr, "Error: read: Failed to parse JSON response for %s: %s\n", content_key, error.text);
            return -EIO;
        }

        value_json = json_object_get(root, "value");
        // Expecting content to be stored as a string in JSON
        if (!json_is_string(value_json)) {
            fprintf(stderr, "Error: read: Value for key %s is not a JSON string\n", content_key);
            json_decref(root);
            // Treat as empty file or return error? Let's return EIO.
            return -EIO; 
        }

        file_content_ptr = json_string_value(value_json);
        content_len_from_json = json_string_length(value_json); // Use this for binary safety
        DEBUG_LOG("hpkv_read(%s): Content length from JSON: %zu\n", path, content_len_from_json);
        
        // Sanity check: Compare content length with metadata size
        if (content_len_from_json != file_size) {
             fprintf(stderr, "Warning: read: Size inconsistency for %s (meta: %zu, content: %zu). Using metadata size.\n", 
                     path, file_size, content_len_from_json);
             // Trust the size from metadata. Adjust read bounds if necessary.
             if (offset >= (off_t)file_size) { 
                 json_decref(root); 
                 DEBUG_LOG("hpkv_read(%s): Offset beyond metadata size after inconsistency check. Returning 0.\n", path);
                 return 0; // EOF based on metadata size
             }
        }

        // Calculate actual bytes to read based on requested size, offset, and file size (from metadata)
        size_t bytes_to_read = size;
        if ((off_t)(offset + bytes_to_read) > (off_t)file_size) {
            bytes_to_read = file_size - offset;
        }
        DEBUG_LOG("hpkv_read(%s): Calculated initial bytes_to_read: %zu\n", path, bytes_to_read);

        // Copy the data into the buffer provided by FUSE
        // Ensure we don't read past the actual content length from JSON either
        if (offset + bytes_to_read > content_len_from_json) {
             if (offset >= (off_t)content_len_from_json) {
                 bytes_to_read = 0; // Offset is beyond the actual content
             } else {
                 bytes_to_read = content_len_from_json - offset; // Read only up to the end of actual content
             }
             if (bytes_to_read > 0) {
                fprintf(stderr, "Warning: read: Adjusted read size for %s due to content length mismatch (requested: %zu, actual: %zu)\n",
                        path, size, bytes_to_read);
             }
             DEBUG_LOG("hpkv_read(%s): Adjusted bytes_to_read due to content length: %zu\n", path, bytes_to_read);
        }

        if (bytes_to_read > 0) {
             DEBUG_LOG("hpkv_read(%s): Copying %zu bytes from offset %ld to buffer.\n", path, bytes_to_read, offset);
             memcpy(buf, file_content_ptr + offset, bytes_to_read);
        }
        ret = bytes_to_read; // Return the number of bytes actually read

        json_decref(root); // Decref the parsed JSON root
        
        // TODO: Update atime after successful read?
        // update_metadata_times(path, 1, 0, 0, NULL); // Update atime only

    } else {
        // Handle API errors (GET content failed)
        if (response.memory) free(response.memory);
        ret = map_http_to_fuse_error(http_code);
        // Don't log ENOENT loudly, could be valid case
        if (ret != -ENOENT) {
            fprintf(stderr, "Error: read: API GET failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        }
        DEBUG_LOG("hpkv_read(%s): API GET failed (%ld). Returning %d.\n", path, http_code, ret);
    }
    DEBUG_LOG("hpkv_read(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// Helper function to update metadata times and optionally size.
// Returns 0 on success, or negative FUSE error code.
static int update_metadata_times(const char *path, int update_atime, int update_mtime, int update_ctime, size_t *new_size_ptr) {
    DEBUG_LOG("update_metadata_times: Called for path: %s (atime:%d, mtime:%d, ctime:%d, size:%p)\n", 
              path, update_atime, update_mtime, update_ctime, new_size_ptr);
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);
    int updated = 0;

    if (!meta_json) {
        DEBUG_LOG("update_metadata_times(%s): Failed to get metadata. Returning -ENOENT.\n", path);
        return -ENOENT; // Cannot update times if metadata doesn't exist
    }

    // Update times/size if requested
    if (update_atime) { 
        DEBUG_LOG("update_metadata_times(%s): Updating atime to %ld\n", path, now);
        json_object_set_new(meta_json, "atime", json_integer(now)); updated = 1; 
    }
    if (update_mtime) { 
        DEBUG_LOG("update_metadata_times(%s): Updating mtime to %ld\n", path, now);
        json_object_set_new(meta_json, "mtime", json_integer(now)); updated = 1; 
    }
    if (new_size_ptr != NULL) { // Optionally update size
         DEBUG_LOG("update_metadata_times(%s): Updating size to %zu\n", path, *new_size_ptr);
         json_object_set_new(meta_json, "size", json_integer(*new_size_ptr)); updated = 1; 
    }
    
    // Always update ctime if any other attribute was changed
    if (updated && update_ctime) { 
        DEBUG_LOG("update_metadata_times(%s): Updating ctime to %ld\n", path, now);
        json_object_set_new(meta_json, "ctime", json_integer(now));
        // Ensure updated flag remains set even if only ctime was triggered by other changes
        updated = 1; 
    }

    // If any attribute was updated, POST the modified metadata
    if (updated) {
        DEBUG_LOG("update_metadata_times(%s): Metadata updated, posting changes...\n", path);
        // post_metadata_json takes ownership of meta_json
        ret = post_metadata_json(path, meta_json);
    } else {
        DEBUG_LOG("update_metadata_times(%s): No metadata changes needed.\n", path);
        json_decref(meta_json); // Nothing changed, just decref the fetched metadata
        ret = 0;
    }
    DEBUG_LOG("update_metadata_times(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// write: Write data to an open file
// This implementation reads the entire existing content, modifies it in memory, and writes it back.
// This is NOT efficient for large files or frequent small writes.
static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_LOG("hpkv_write: Called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    // Suppress unused parameter warning
    (void) fi;

    char content_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL, *request_body_json = NULL;
    json_error_t error;
    int ret = 0;
    char *old_content = NULL;
    size_t old_size = 0;
    char *new_content = NULL;
    size_t new_size = 0;
    char *request_json_str = NULL;

    // 1. Get current authoritative size from metadata
    DEBUG_LOG("hpkv_write(%s): Getting metadata for size check...\n", path);
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            old_size = (size_t)json_integer_value(j_size);
            DEBUG_LOG("hpkv_write(%s): Size from metadata: %zu\n", path, old_size);
        }
        json_decref(meta_json); // Decref metadata JSON
    } else {
        DEBUG_LOG("hpkv_write(%s): Failed to get metadata. Returning -ENOENT.\n", path);
        return -ENOENT; // Cannot write if metadata doesn't exist
    }

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    // 2. Get current content (Read)
    // Only fetch if the write doesn't start at 0 and completely overwrite old content?
    // For simplicity and correctness with partial overwrites, fetch always for now.
    if (old_size > 0) { // No need to fetch if file is currently empty
        DEBUG_LOG("hpkv_write(%s): Old size > 0, fetching existing content...\n", path);
        encoded_key = url_encode(content_key);
        if (!encoded_key) { return -EIO; }
        if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
        snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
        free(encoded_key);

        http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);
        if (http_code == 200 && response.memory) {
            DEBUG_LOG("hpkv_write(%s): API GET successful (200 OK). Parsing existing content.\n", path);
            root = json_loads(response.memory, 0, &error);
            free(response.memory); response.memory = NULL;
            if (root) {
                value_json = json_object_get(root, "value");
                if (json_is_string(value_json)) {
                    const char* temp_content = json_string_value(value_json);
                    size_t temp_len = json_string_length(value_json);
                    DEBUG_LOG("hpkv_write(%s): Existing content length from JSON: %zu\n", path, temp_len);
                    // Verify against metadata size, prioritize metadata size
                    if (temp_len != old_size) {
                         fprintf(stderr, "Warning: write: Size inconsistency for %s (meta: %zu, content: %zu). Using metadata size.\n", 
                                 path, old_size, temp_len);
                         // Adjust effective old_size based on metadata if content is shorter
                         old_size = (old_size < temp_len) ? old_size : temp_len; 
                    }
                    // Allocate and copy the relevant part of old content
                    old_content = malloc(old_size); 
                    if (old_content) {
                        memcpy(old_content, temp_content, old_size);
                        DEBUG_LOG("hpkv_write(%s): Copied %zu bytes of existing content.\n", path, old_size);
                    } else {
                         json_decref(root); return -ENOMEM;
                    }
                } else {
                     fprintf(stderr, "Warning: write: Existing value for %s is not a string, treating as empty.\n", content_key);
                     old_size = 0; // Reset size if content wasn't string
                }
                json_decref(root);
            } else {
                 fprintf(stderr, "Warning: write: Failed to parse existing content JSON for %s: %s. Treating as empty.\n", content_key, error.text);
                 old_size = 0; // Assume empty on parse failure
            }
        } else if (http_code == 404) {
            // Content key doesn't exist, but metadata said size > 0. Inconsistency.
            fprintf(stderr, "Warning: write: Metadata size for %s is %zu, but content key not found (404). Treating as empty.\n", path, old_size);
            if (response.memory) free(response.memory); response.memory = NULL;
            old_size = 0;
        } else {
            // Other API error fetching content
            fprintf(stderr, "Error: write: Failed to GET existing content for %s, HTTP: %ld\n", content_key, http_code);
            if (response.memory) free(response.memory);
            return map_http_to_fuse_error(http_code);
        }
    } else {
        DEBUG_LOG("hpkv_write(%s): Old size is 0, no need to fetch existing content.\n", path);
    }

    // 3. Prepare new content buffer (Modify)
    // Calculate the required size of the new buffer
    new_size = offset + size;
    if (new_size < old_size) {
        new_size = old_size; // Write doesn't implicitly truncate in POSIX
    }
    DEBUG_LOG("hpkv_write(%s): Calculated new content size: %zu\n", path, new_size);

    new_content = malloc(new_size);
    if (!new_content) {
        fprintf(stderr, "Error: write: Failed to allocate memory (%zu bytes) for new content\n", new_size);
        free(old_content);
        return -ENOMEM;
    }

    // Copy the part of old content before the offset
    size_t pre_offset_size = (offset < (off_t)old_size) ? offset : old_size;
    if (old_content && pre_offset_size > 0) {
        memcpy(new_content, old_content, pre_offset_size);
        DEBUG_LOG("hpkv_write(%s): Copied %zu bytes from old content (before offset).\n", path, pre_offset_size);
    }

    // If writing starts beyond the old end, fill the gap with zeros (POSIX behavior)
    if (offset > (off_t)old_size) {
        DEBUG_LOG("hpkv_write(%s): Filling gap from %zu to %ld with zeros.\n", path, old_size, offset);
        memset(new_content + old_size, 0, offset - old_size);
    }

    // Copy the new data from the write buffer
    DEBUG_LOG("hpkv_write(%s): Copying %zu bytes from input buffer to offset %ld.\n", path, size, offset);
    memcpy(new_content + offset, buf, size);

    // If the write finished before the old end, copy the remaining old data
    if (old_content && (offset + size < old_size)) {
        size_t remaining_offset = offset + size;
        size_t remaining_size = old_size - remaining_offset;
        memcpy(new_content + remaining_offset, old_content + remaining_offset, remaining_size);
        DEBUG_LOG("hpkv_write(%s): Copied %zu bytes from old content (after write end).\n", path, remaining_size);
    }
    
    free(old_content); // Free the old content buffer now

    // 4. POST the new content (Write)
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    // Use json_stringn for binary safety, passing the calculated new_size
    json_object_set_new(request_body_json, "value", json_stringn(new_content, new_size));
    
    request_json_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    free(new_content); // Content is now safely in the JSON string

    if (!request_json_str) { 
        fprintf(stderr, "Error: write: Failed to dump content JSON for %s\n", content_key);
        return -EIO; 
    }

    DEBUG_LOG("hpkv_write(%s): Posting new content (size %zu) for key %s...\n", path, new_size, content_key);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Error: write: Failed to POST content for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        return ret;
    }
    DEBUG_LOG("hpkv_write(%s): Content POST successful.\n", path);

    // 5. Update metadata (size, mtime, ctime)
    DEBUG_LOG("hpkv_write(%s): Updating metadata (size=%zu, mtime, ctime)...\n", path, new_size);
    ret = update_metadata_times(path, 0 /*atime*/, 1 /*mtime*/, 1 /*ctime*/, &new_size);
    if (ret != 0) {
        fprintf(stderr, "Warning: write: Failed to update metadata for %s after write, FUSE: %d\n", path, ret);
        // Write succeeded, but metadata update failed. Return success for write, but log warning.
        // Alternatively, could return error here? Let's return success for write size.
    }

    DEBUG_LOG("hpkv_write(%s): Finished, returning write size %zu\n", path, size);
    return size; // Return the number of bytes requested to be written (POSIX standard)
}

// truncate: Change the size of a file
static int hpkv_truncate(const char *path, off_t size) {
    DEBUG_LOG("hpkv_truncate: Called for path: %s, size: %ld\n", path, size);
    char content_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL, *request_body_json = NULL;
    json_error_t error;
    int ret = 0;
    char *old_content = NULL;
    size_t old_size = 0;
    char *new_content = NULL;
    size_t new_size = (size_t)size; // Target size
    char *request_json_str = NULL;

    if (size < 0) return -EINVAL; // Cannot truncate to negative size

    // 1. Get current authoritative size from metadata
    DEBUG_LOG("hpkv_truncate(%s): Getting metadata for size check...\n", path);
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            old_size = (size_t)json_integer_value(j_size);
            DEBUG_LOG("hpkv_truncate(%s): Size from metadata: %zu\n", path, old_size);
        }
        json_decref(meta_json);
    } else {
        DEBUG_LOG("hpkv_truncate(%s): Failed to get metadata. Returning -ENOENT.\n", path);
        return -ENOENT; // Cannot truncate if metadata doesn't exist
    }

    // If size is the same, just update times and return success
    if (new_size == old_size) {
        DEBUG_LOG("hpkv_truncate(%s): New size matches old size. Updating times only.\n", path);
        return update_metadata_times(path, 0 /*atime*/, 1 /*mtime*/, 1 /*ctime*/, NULL);
    }

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    // 2. Get current content (Read) - Needed for both shrinking and extending
    if (old_size > 0) { // No need to fetch if file is currently empty
        DEBUG_LOG("hpkv_truncate(%s): Old size > 0, fetching existing content...\n", path);
        encoded_key = url_encode(content_key);
        if (!encoded_key) { return -EIO; }
        if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
        snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
        free(encoded_key);

        http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);
        if (http_code == 200 && response.memory) {
            DEBUG_LOG("hpkv_truncate(%s): API GET successful (200 OK). Parsing existing content.\n", path);
            root = json_loads(response.memory, 0, &error);
            free(response.memory); response.memory = NULL;
            if (root) {
                value_json = json_object_get(root, "value");
                if (json_is_string(value_json)) {
                    const char* temp_content = json_string_value(value_json);
                    size_t temp_len = json_string_length(value_json);
                    DEBUG_LOG("hpkv_truncate(%s): Existing content length from JSON: %zu\n", path, temp_len);
                    if (temp_len != old_size) { /* Size inconsistency warning */ 
                         fprintf(stderr, "Warning: truncate: Size inconsistency for %s (meta: %zu, content: %zu). Using metadata size.\n", 
                                 path, old_size, temp_len);
                         old_size = (old_size < temp_len) ? old_size : temp_len; 
                    }
                    old_content = malloc(old_size);
                    if (old_content) {
                        memcpy(old_content, temp_content, old_size);
                        DEBUG_LOG("hpkv_truncate(%s): Copied %zu bytes of existing content.\n", path, old_size);
                    } else {
                         json_decref(root); return -ENOMEM;
                    }
                } else { old_size = 0; }
                json_decref(root);
            } else { old_size = 0; }
        } else if (http_code == 404) {
             fprintf(stderr, "Warning: truncate: Metadata size for %s is %zu, but content key not found (404). Treating as empty.\n", path, old_size);
             if (response.memory) free(response.memory); response.memory = NULL;
             old_size = 0;
        } else {
            fprintf(stderr, "Error: truncate: Failed GET for %s, HTTP: %ld\n", content_key, http_code);
            if (response.memory) free(response.memory);
            return map_http_to_fuse_error(http_code);
        }
    } else {
         DEBUG_LOG("hpkv_truncate(%s): Old size is 0, no need to fetch existing content.\n", path);
    }

    // 3. Create new content buffer (Modify)
    DEBUG_LOG("hpkv_truncate(%s): Allocating new content buffer of size %zu\n", path, new_size);
    new_content = malloc(new_size);
    if (!new_content) { free(old_content); return -ENOMEM; }

    if (new_size == 0) {
        // Special case: Truncating to zero size
        DEBUG_LOG("hpkv_truncate(%s): Truncating to zero size.\n", path);
    } else if (new_size < old_size) {
        // Shrinking: Copy the prefix from old content
        DEBUG_LOG("hpkv_truncate(%s): Shrinking file. Copying first %zu bytes from old content.\n", path, new_size);
        if (old_content) {
            memcpy(new_content, old_content, new_size);
        }
        // If old_content was NULL (e.g., due to inconsistency), new_content remains uninitialized (effectively zeroed by malloc? No, use memset)
        else {
             memset(new_content, 0, new_size);
        }
    } else { // Extending (new_size > old_size)
        DEBUG_LOG("hpkv_truncate(%s): Extending file. Copying %zu bytes of old content and padding with zeros.\n", path, old_size);
        // Copy all of the old content
        if (old_content && old_size > 0) {
            memcpy(new_content, old_content, old_size);
        }
        // Pad the extension with null bytes (POSIX behavior)
        memset(new_content + old_size, 0, new_size - old_size);
    }
    free(old_content); // Free old buffer

    // 4. POST new content (Write)
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    // Use json_stringn for binary safety, passing the target new_size
    json_object_set_new(request_body_json, "value", json_stringn(new_content, new_size));
    
    request_json_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    free(new_content); // Content is now in JSON string

    if (!request_json_str) { 
        fprintf(stderr, "Error: truncate: Failed to dump content JSON for %s\n", content_key);
        return -EIO; 
    }

    DEBUG_LOG("hpkv_truncate(%s): Posting new content (size %zu) for key %s...\n", path, new_size, content_key);
    http_code = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Error: truncate: Failed to POST content for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        return ret;
    }
    DEBUG_LOG("hpkv_truncate(%s): Content POST successful.\n", path);

    // 5. Update metadata (size, mtime, ctime)
    DEBUG_LOG("hpkv_truncate(%s): Updating metadata (size=%zu, mtime, ctime)...\n", path, new_size);
    ret = update_metadata_times(path, 0 /*atime*/, 1 /*mtime*/, 1 /*ctime*/, &new_size);
    if (ret != 0) {
        fprintf(stderr, "Warning: truncate: Failed to update metadata for %s after truncate, FUSE: %d\n", path, ret);
        // Truncate POST succeeded, but metadata update failed. Return success for truncate.
    }

    DEBUG_LOG("hpkv_truncate(%s): Finished successfully, returning 0\n", path);
    return 0; // Success
}

// unlink: Delete a file
static int hpkv_unlink(const char *path) {
    DEBUG_LOG("hpkv_unlink: Called for path: %s\n", path);
    char content_key[1024];
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code_content, http_code_meta;
    int ret_content = 0, ret_meta = 0;

    // Check if it's a directory - unlink should fail for directories
    struct stat stbuf;
    DEBUG_LOG("hpkv_unlink(%s): Checking if path is a directory...\n", path);
    int getattr_ret = hpkv_getattr(path, &stbuf);
    if (getattr_ret == 0 && S_ISDIR(stbuf.st_mode)) {
        DEBUG_LOG("hpkv_unlink(%s): Path is a directory. Returning -EISDIR.\n", path);
        return -EISDIR; // Cannot unlink a directory
    }
    // If getattr failed with ENOENT, that's okay, we'll try deleting anyway.
    // If it failed with another error, return that error.
    if (getattr_ret != 0 && getattr_ret != -ENOENT) {
        DEBUG_LOG("hpkv_unlink(%s): getattr failed (%d) but not ENOENT. Returning error.\n", path, getattr_ret);
        return getattr_ret;
    }
    DEBUG_LOG("hpkv_unlink(%s): Path is not a directory or does not exist. Proceeding with deletion attempts.\n", path);

    // Prepare keys
    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';
    get_meta_key(path, meta_key, sizeof(meta_key));

    // 1. Delete content key
    encoded_key = url_encode(content_key);
    if (!encoded_key) { return -EIO; }
    if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    
    DEBUG_LOG("hpkv_unlink(%s): Performing DELETE request for content key %s\n", path, content_key);
    http_code_content = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) { free(response.memory); response.memory = NULL; }
    ret_content = map_http_to_fuse_error(http_code_content);
    // Log errors other than Not Found
    if (ret_content != 0 && ret_content != -ENOENT) {
         fprintf(stderr, "Warning: unlink: Content DELETE failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code_content, ret_content);
    }
    DEBUG_LOG("hpkv_unlink(%s): Content DELETE result: %d\n", path, ret_content);

    // 2. Delete metadata key
    encoded_key = url_encode(meta_key);
    if (!encoded_key) { return -EIO; } // Should we try to proceed if content delete failed?
    if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    
    DEBUG_LOG("hpkv_unlink(%s): Performing DELETE request for meta key %s\n", path, meta_key);
    http_code_meta = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) { free(response.memory); response.memory = NULL; }
    ret_meta = map_http_to_fuse_error(http_code_meta);
    // Log errors other than Not Found
     if (ret_meta != 0 && ret_meta != -ENOENT) {
         fprintf(stderr, "Warning: unlink: Meta DELETE failed for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code_meta, ret_meta);
    }
    DEBUG_LOG("hpkv_unlink(%s): Meta DELETE result: %d\n", path, ret_meta);

    // POSIX unlink should return success if the file is gone.
    // Return success (0) if either delete succeeded or returned ENOENT.
    // Return an error only if both failed with something other than ENOENT?
    // Let's return success if the *metadata* delete worked or was ENOENT, as metadata defines existence.
    if (ret_meta == 0 || ret_meta == -ENOENT) {
        DEBUG_LOG("hpkv_unlink(%s): Finished successfully (meta delete ok or ENOENT). Returning 0.\n", path);
        return 0; 
    } else {
        // If meta delete failed with a real error, return that error.
        DEBUG_LOG("hpkv_unlink(%s): Finished with error (meta delete failed). Returning %d.\n", path, ret_meta);
        return ret_meta; 
    }
}

// rename: Rename/move a file or directory
// WARNING: THIS IS NOT ATOMIC. It's implemented as copy-then-delete.
static int hpkv_rename(const char *from_path, const char *to_path) {
    DEBUG_LOG("hpkv_rename: Called from: %s, to: %s\n", from_path, to_path);
    char from_content_key[1024], to_content_key[1024];
    char from_meta_key[1024], to_meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response_get, response_post;
    long http_code;
    json_t *root = NULL, *value_json = NULL, *request_body_json = NULL;
    json_error_t error;
    char *content_value = NULL; // Buffer for file content (binary safe)
    size_t content_size = 0;
    char *meta_value_str = NULL; // Metadata stored as JSON string
    char *post_body_str = NULL;
    int ret = 0;
    struct stat stbuf_from = {0}, stbuf_to = {0};
    int from_is_dir = 0;
    // int to_exists = 0; // Variable 'to_exists' set but not used [-Wunused-but-set-variable]
    int to_is_dir = 0;

    // Prepare all key names
    strncpy(from_content_key, from_path, sizeof(from_content_key) - 1); from_content_key[sizeof(from_content_key) - 1] = '\0';
    strncpy(to_content_key, to_path, sizeof(to_content_key) - 1); to_content_key[sizeof(to_content_key) - 1] = '\0';
    get_meta_key(from_path, from_meta_key, sizeof(from_meta_key));
    get_meta_key(to_path, to_meta_key, sizeof(to_meta_key));
    DEBUG_LOG("hpkv_rename: Keys: from_content=%s, to_content=%s, from_meta=%s, to_meta=%s\n", 
              from_content_key, to_content_key, from_meta_key, to_meta_key);

    // 1. Check source exists and get its type
    DEBUG_LOG("hpkv_rename(%s -> %s): Checking source path...\n", from_path, to_path);
    if (hpkv_getattr(from_path, &stbuf_from) != 0) {
        DEBUG_LOG("hpkv_rename(%s -> %s): Source does not exist. Returning -ENOENT.\n", from_path, to_path);
        return -ENOENT; // Source does not exist
    }
    from_is_dir = S_ISDIR(stbuf_from.st_mode);
    DEBUG_LOG("hpkv_rename(%s -> %s): Source exists (is_dir=%d).\n", from_path, to_path, from_is_dir);

    // 2. Check destination
    DEBUG_LOG("hpkv_rename(%s -> %s): Checking destination path...\n", from_path, to_path);
    if (hpkv_getattr(to_path, &stbuf_to) == 0) {
        // to_exists = 1;
        to_is_dir = S_ISDIR(stbuf_to.st_mode);
        DEBUG_LOG("hpkv_rename(%s -> %s): Destination exists (is_dir=%d).\n", from_path, to_path, to_is_dir);

        // POSIX rename constraints:
        if (from_is_dir && !to_is_dir) {
             DEBUG_LOG("hpkv_rename(%s -> %s): Cannot rename dir to non-dir. Returning -ENOTDIR.\n", from_path, to_path);
             return -ENOTDIR; 
        }
        if (!from_is_dir && to_is_dir) {
             DEBUG_LOG("hpkv_rename(%s -> %s): Cannot rename non-dir to dir. Returning -EISDIR.\n", from_path, to_path);
             return -EISDIR;  
        }
        
        // If both are dirs, 'to' must be empty
        if (from_is_dir && to_is_dir) {
            // TODO: Check if 'to_path' is empty using readdir logic. Return -ENOTEMPTY if not.
            fprintf(stderr, "Warning: rename: Destination directory emptiness check not implemented.\n");
        }
        
        // Destination exists, need to remove it first (atomicity violation!)
        fprintf(stderr, "Warning: rename: Destination %s exists, attempting to remove it first (non-atomic).\n", to_path);
        if (to_is_dir) {
            ret = hpkv_rmdir(to_path); // Assumes rmdir checks emptiness (or fails appropriately)
        } else {
            ret = hpkv_unlink(to_path);
        }
        if (ret != 0) {
             fprintf(stderr, "Error: rename: Failed to remove existing destination %s, FUSE: %d\n", to_path, ret);
             return ret; // Cannot proceed if destination removal fails
        }
        DEBUG_LOG("hpkv_rename(%s -> %s): Successfully removed existing destination.\n", from_path, to_path);
    } else {
        DEBUG_LOG("hpkv_rename(%s -> %s): Destination does not exist.\n", from_path, to_path);
        // If getattr failed on 'to', check if parent directory exists?
        // FUSE might handle this check before calling rename.
    }

    // --- Copy Phase --- 
    DEBUG_LOG("hpkv_rename(%s -> %s): Starting copy phase...\n", from_path, to_path);

    // 3. Get 'from' metadata string
    DEBUG_LOG("hpkv_rename(%s -> %s): Getting source metadata (%s)...\n", from_path, to_path, from_meta_key);
    encoded_key = url_encode(from_meta_key);
    if (!encoded_key) { return -EIO; }
    if (encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response_get, 3);
    if (http_code != 200 || !response_get.memory) { 
        fprintf(stderr, "Error: rename: Failed GET from_meta %s, HTTP: %ld\n", from_meta_key, http_code);
        if (response_get.memory) free(response_get.memory); 
        return map_http_to_fuse_error(http_code); 
    }
    root = json_loads(response_get.memory, 0, &error);
    free(response_get.memory); response_get.memory = NULL;
    if (!root) { fprintf(stderr, "Error: rename: Failed parse from_meta JSON %s\n", from_meta_key); return -EIO; }
    value_json = json_object_get(root, "value");
    // Metadata value should itself be a JSON string containing the metadata object
    if (!json_is_string(value_json)) { 
        fprintf(stderr, "Error: rename: from_meta value is not a JSON string %s\n", from_meta_key);
        json_decref(root); return -EIO; 
    }
    meta_value_str = strdup(json_string_value(value_json)); // Copy the metadata JSON string
    json_decref(root);
    if (!meta_value_str) return -ENOMEM;
    DEBUG_LOG("hpkv_rename(%s -> %s): Successfully retrieved source metadata string.\n", from_path, to_path);

    // 4. Get 'from' content (only if it's a file)
    if (!from_is_dir) {
        DEBUG_LOG("hpkv_rename(%s -> %s): Getting source content (%s)...\n", from_path, to_path, from_content_key);
        encoded_key = url_encode(from_content_key);
        if (!encoded_key) { free(meta_value_str); return -EIO; }
        if (encoded_key[0] == '\0') { free(encoded_key); free(meta_value_str); return -EIO; }
        snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
        free(encoded_key);
        
        http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response_get, 3);
        if (http_code == 200 && response_get.memory) {
            root = json_loads(response_get.memory, 0, &error);
            free(response_get.memory); response_get.memory = NULL;
            if (root) {
                 value_json = json_object_get(root, "value");
                 if (json_is_string(value_json)) {
                     const char* temp_content = json_string_value(value_json);
                     content_size = json_string_length(value_json);
                     content_value = malloc(content_size);
                     if (content_value) {
                         memcpy(content_value, temp_content, content_size);
                         DEBUG_LOG("hpkv_rename(%s -> %s): Successfully retrieved source content (size %zu).\n", from_path, to_path, content_size);
                     } else {
                         ret = -ENOMEM;
                     }
                 } else { 
                     // Content value is not a string? Treat as empty.
                     fprintf(stderr, "Warning: rename: from_content value is not a string %s. Treating as empty.\n", from_content_key);
                     content_size = 0; 
                     content_value = NULL; // Or strdup("")? Let's use NULL and size 0.
                 }
                 json_decref(root);
            } else { 
                fprintf(stderr, "Warning: rename: Failed parse from_content JSON %s. Treating as empty.\n", from_content_key);
                content_size = 0; content_value = NULL; ret = -EIO; // Indicate potential issue
            }
        } else if (http_code == 404) {
             // Content key not found, maybe inconsistent state? Treat as empty.
             fprintf(stderr, "Warning: rename: from_content key not found %s. Treating as empty.\n", from_content_key);
             if (response_get.memory) free(response_get.memory); response_get.memory = NULL;
             content_size = 0; content_value = NULL; 
        } else {
            fprintf(stderr, "Error: rename: Failed GET from_content %s, HTTP: %ld\n", from_content_key, http_code);
            if (response_get.memory) free(response_get.memory);
            ret = map_http_to_fuse_error(http_code);
        }
        if (ret != 0 && ret != -EIO) { // If GET failed hard, abort
             free(meta_value_str); free(content_value); 
             return ret; 
        }
        // Reset ret if it was EIO from parsing, proceed with potentially empty content
        if (ret == -EIO) ret = 0;
    } else {
        DEBUG_LOG("hpkv_rename(%s -> %s): Source is directory, skipping content copy.\n", from_path, to_path);
    }

    // 5. POST 'to' metadata
    DEBUG_LOG("hpkv_rename(%s -> %s): Posting destination metadata (%s)...\n", from_path, to_path, to_meta_key);
    request_body_json = json_object();
    if (!request_body_json) { free(meta_value_str); free(content_value); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(to_meta_key));
    // The value is the JSON string we fetched earlier
    json_object_set_new(request_body_json, "value", json_string(meta_value_str));
    post_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    if (!post_body_str) { 
        fprintf(stderr, "Error: rename: Failed dump to_meta JSON %s\n", to_meta_key);
        free(meta_value_str); free(content_value); return -EIO; 
    }
    
    http_code = perform_hpkv_request_with_retry("POST", "/record", post_body_str, &response_post, 3);
    free(post_body_str); post_body_str = NULL;
    if (response_post.memory) { free(response_post.memory); response_post.memory = NULL; }
    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "Error: rename: Failed POST to_meta %s, HTTP: %ld, FUSE: %d\n", to_meta_key, http_code, ret);
        free(meta_value_str); free(content_value);
        return ret; // Fail early if cannot create destination metadata
    }
    DEBUG_LOG("hpkv_rename(%s -> %s): Successfully posted destination metadata.\n", from_path, to_path);

    // 6. POST 'to' content (only if file)
    if (!from_is_dir) {
        DEBUG_LOG("hpkv_rename(%s -> %s): Posting destination content (%s)...\n", from_path, to_path, to_content_key);
        request_body_json = json_object();
        if (!request_body_json) { free(meta_value_str); free(content_value); /* TODO: Delete to_meta? */ return -ENOMEM; }
        json_object_set_new(request_body_json, "key", json_string(to_content_key));
        // Use json_stringn for binary safety
        json_object_set_new(request_body_json, "value", json_stringn(content_value ? content_value : "", content_size));
        post_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
        json_decref(request_body_json);
        if (!post_body_str) { 
            fprintf(stderr, "Error: rename: Failed dump to_content JSON %s\n", to_content_key);
            free(meta_value_str); free(content_value); /* TODO: Delete to_meta? */ return -EIO; 
        }
        
        http_code = perform_hpkv_request_with_retry("POST", "/record", post_body_str, &response_post, 3);
        free(post_body_str); post_body_str = NULL;
        if (response_post.memory) { free(response_post.memory); response_post.memory = NULL; }
        ret = map_http_to_fuse_error(http_code);
        if (ret != 0) {
            fprintf(stderr, "Error: rename: Failed POST to_content %s, HTTP: %ld, FUSE: %d\n", to_content_key, http_code, ret);
            free(meta_value_str); free(content_value);
            // TODO: Attempt cleanup: delete 'to_meta' key we just created?
            return ret;
        }
        DEBUG_LOG("hpkv_rename(%s -> %s): Successfully posted destination content.\n", from_path, to_path);
    }

    // --- Delete Phase --- 
    DEBUG_LOG("hpkv_rename(%s -> %s): Starting delete phase for source...\n", from_path, to_path);
    // If copy succeeded, attempt to delete the source.

    // 7. DELETE 'from' (meta and content if file)
    int delete_ret = 0;
    if (from_is_dir) {
        // Only need to delete the metadata key for directories
        DEBUG_LOG("hpkv_rename(%s -> %s): Deleting source directory metadata...\n", from_path, to_path);
        delete_ret = hpkv_rmdir(from_path); // This only deletes meta key (and checks type)
    } else {
        // Use unlink which deletes both content and meta keys
        DEBUG_LOG("hpkv_rename(%s -> %s): Deleting source file content and metadata...\n", from_path, to_path);
        delete_ret = hpkv_unlink(from_path);
    }
    if (delete_ret != 0) {
         // Log warning, but return success for rename as copy succeeded.
         fprintf(stderr, "Warning: rename: Failed DELETE from %s, FUSE: %d. Source may still exist.\n", from_path, delete_ret);
    }
    DEBUG_LOG("hpkv_rename(%s -> %s): Delete phase completed (result %d).\n", from_path, to_path, delete_ret);

    // Cleanup allocated memory
    free(meta_value_str);
    free(content_value);
    DEBUG_LOG("hpkv_rename(%s -> %s): Finished successfully, returning 0.\n", from_path, to_path);
    return 0; // Return success as the 'to' path now exists with the content/metadata.
}

// --- FUSE attribute setting functions (for FUSE_USE_VERSION 26) ---
// These are separate operations in FUSE 2.x, unlike the single setattr in FUSE 3.x

// chmod: Change file/directory permissions
static int hpkv_chmod(const char *path, mode_t mode) {
    DEBUG_LOG("hpkv_chmod: Called for path: %s, mode: 0%o\n", path, mode);
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);

    if (!meta_json) return -ENOENT;

    // Get current mode to preserve file type (S_IFREG/S_IFDIR)
    mode_t current_mode = 0;
    json_t *j_mode = json_object_get(meta_json, "mode");
    if (json_is_integer(j_mode)) {
        current_mode = (mode_t)json_integer_value(j_mode);
    }
    // Combine the existing file type with the new permission bits
    mode_t new_mode = (current_mode & S_IFMT) | (mode & ~S_IFMT);
    DEBUG_LOG("hpkv_chmod(%s): Old mode=0%o, New mode=0%o\n", path, current_mode, new_mode);

    // Update mode and ctime in the metadata object
    json_object_set_new(meta_json, "mode", json_integer(new_mode));
    json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime

    // POST the updated metadata (post_metadata_json takes ownership)
    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_chmod(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// chown: Change file/directory owner/group
static int hpkv_chown(const char *path, uid_t uid, gid_t gid) {
    DEBUG_LOG("hpkv_chown: Called for path: %s, uid: %d, gid: %d\n", path, (int)uid, (int)gid);
    #ifdef _WIN32
        // chown is not applicable on Windows in the same way.
        // Return EPERM or similar? Or just ignore?
        (void)path; (void)uid; (void)gid; // Suppress unused warnings
        return -EPERM; // Operation not supported
    #else
        json_t *meta_json = get_metadata_json(path);
        int ret = 0;
        time_t now = time(NULL);
        int updated = 0;

        if (!meta_json) return -ENOENT;

        // FUSE passes -1 if uid/gid shouldn't be changed
        if (uid != (uid_t)-1) {
            DEBUG_LOG("hpkv_chown(%s): Updating uid to %d\n", path, (int)uid);
            json_object_set_new(meta_json, "uid", json_integer(uid));
            updated = 1;
        }
        if (gid != (gid_t)-1) {
            DEBUG_LOG("hpkv_chown(%s): Updating gid to %d\n", path, (int)gid);
            json_object_set_new(meta_json, "gid", json_integer(gid));
            updated = 1;
        }

        if (updated) {
            DEBUG_LOG("hpkv_chown(%s): Updating ctime and posting metadata...\n", path);
            json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime
            // POST the updated metadata (post_metadata_json takes ownership)
            ret = post_metadata_json(path, meta_json);
        } else {
            DEBUG_LOG("hpkv_chown(%s): No changes needed.\n", path);
            json_decref(meta_json); // No changes, just decref the fetched metadata
            ret = 0;
        }
        DEBUG_LOG("hpkv_chown(%s): Finished, returning %d\n", path, ret);
        return ret;
    #endif
}

// utimens: Change access and modification times
static int hpkv_utimens(const char *path, const struct timespec ts[2]) {
    DEBUG_LOG("hpkv_utimens: Called for path: %s, atime=%ld, mtime=%ld\n", path, ts[0].tv_sec, ts[1].tv_sec);
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);

    if (!meta_json) return -ENOENT;

    // ts[0] is access time (atime), ts[1] is modification time (mtime)
    // TODO: Handle UTIME_NOW and UTIME_OMIT if FUSE passes them via tv_nsec?
    // For now, assume valid seconds are passed.
    json_object_set_new(meta_json, "atime", json_integer(ts[0].tv_sec));
    json_object_set_new(meta_json, "mtime", json_integer(ts[1].tv_sec));
    json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime

    // POST the updated metadata (post_metadata_json takes ownership)
    DEBUG_LOG("hpkv_utimens(%s): Posting updated metadata...\n", path);
    ret = post_metadata_json(path, meta_json);
    DEBUG_LOG("hpkv_utimens(%s): Finished, returning %d\n", path, ret);
    return ret;
}

// --- FUSE Operations Structure ---

static struct fuse_operations hpkv_oper = {
    .getattr = hpkv_getattr,
    .readdir = hpkv_readdir,
    .mkdir   = hpkv_mkdir,
    .rmdir   = hpkv_rmdir,
    .create  = hpkv_create,
    .open    = hpkv_open,
    .read    = hpkv_read,
    .write   = hpkv_write,
    .truncate= hpkv_truncate,
    .unlink  = hpkv_unlink,
    .rename  = hpkv_rename,
    // Use specific attribute functions for FUSE 2.x compatibility
    .chmod   = hpkv_chmod,
    .chown   = hpkv_chown,
    .utimens = hpkv_utimens,
    // .setattr is not used in FUSE 2.x when specific functions are provided
};

// --- Main Function --- 

// Define command line options for FUSE
#define HPKV_OPT_KEY(t, p, v) { t, offsetof(struct hpkv_options, p), v }
static const struct fuse_opt hpkv_opts[] = {
    // Option template: "--long-option[=format]", offset_in_struct, value_to_set
    HPKV_OPT_KEY("--api-url=%s", api_base_url, 0),
    HPKV_OPT_KEY("--api-key=%s", api_key, 0),
    // Standard FUSE options are handled automatically
    FUSE_OPT_END
};

// Custom option processor (optional, can be used for complex validation)
// Returning 1 tells fuse_opt_parse to keep the option for fuse_main
// Returning 0 tells fuse_opt_parse that we handled it and it should be removed
// Returning -1 signals an error
static int hpkv_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    // Suppress unused parameter warnings
    (void) data; (void) arg; (void) key; (void) outargs;
    
    // We let fuse_opt_parse handle the options defined in hpkv_opts.
    // We also let FUSE handle its own standard options.
    // If we had custom options not fitting the template, we could handle them here.
    return 1; 
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct hpkv_options options = {0}; // Parsed options will be stored here
    hpkv_config config = {0}; // Configuration passed to FUSE private_data
    int fuse_ret;

    // Set default values (can be overridden by command line)
    // No default for api_url or api_key - they are required.

    // Parse command line options
    // fuse_opt_parse fills the 'options' struct based on hpkv_opts definition
    if (fuse_opt_parse(&args, &options, hpkv_opts, hpkv_opt_proc) == -1) {
        fprintf(stderr, "Error: Failed to parse FUSE options\n");
        return 1;
    }

    // Validate required options
    if (!options.api_key) {
        fprintf(stderr, "Error: --api-key is required.\n");
        fprintf(stderr, "Usage: %s mountpoint --api-key=<key> --api-url=<url> [FUSE options]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }
    if (!options.api_base_url || options.api_base_url[0] == '\0') {
        fprintf(stderr, "Error: --api-url is required and cannot be empty.\n");
        fprintf(stderr, "Usage: %s mountpoint --api-key=<key> --api-url=<url> [FUSE options]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }

    // Copy parsed options to the config struct that will be passed to FUSE
    // Use strdup to ensure the strings persist
    config.api_base_url = strdup(options.api_base_url);
    config.api_key = strdup(options.api_key);
    if (!config.api_base_url || !config.api_key) {
         fprintf(stderr, "Error: Failed to allocate memory for config strings\n");
         free(config.api_base_url); // free is safe on NULL
         free(config.api_key);
         fuse_opt_free_args(&args);
         return 1;
    }

    // Initialize libcurl globally (thread-safe)
    curl_global_init(CURL_GLOBAL_DEFAULT);

    fprintf(stdout, "Starting HPKV FUSE filesystem (hpkvfs v0.1.1).\n");
    fprintf(stdout, "  API URL: %s\n", config.api_base_url);
    fprintf(stdout, "Mounting filesystem...\n");

    // Run the FUSE main loop
    // Pass the remaining arguments (args), the operations struct (hpkv_oper),
    // and the configuration struct (config) as private data.
    fuse_ret = fuse_main(args.argc, args.argv, &hpkv_oper, &config);

    fprintf(stdout, "HPKV FUSE filesystem unmounted (Exit code: %d).\n", fuse_ret);

    // Cleanup
    fuse_opt_free_args(&args); // Free arguments processed by fuse_opt_parse
    curl_global_cleanup();     // Cleanup libcurl global state
    free(config.api_base_url); // Free the duplicated config strings
    free(config.api_key);

    return fuse_ret;
}

