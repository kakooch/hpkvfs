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
    json_decref(meta_json
(Content truncated due to size limit. Use line ranges to read in chunks)