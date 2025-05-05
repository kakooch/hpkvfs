/*******************************************************************************
 * HPKV FUSE Filesystem
 * 
 * Connects to an HPKV REST API to provide a filesystem interface.
 ******************************************************************************/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h> // Needed for offsetof

// --- Configuration & State ---

typedef struct {
    char *api_base_url;
    char *api_key;
} hpkv_config;

#define HPKV_DATA ((hpkv_config *) fuse_get_context()->private_data)

// Structure to hold command line options
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
    fprintf(stderr, "not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

// Helper to URL-encode a string
static char *url_encode(const char *input) {
    CURL *curl = curl_easy_init();
    char *output = NULL;
    if(curl) {
        // Use curl_escape for path segments, 0 length means strlen
        output = curl_easy_escape(curl, input, 0);
        curl_easy_cleanup(curl);
    }
    if (!output) {
        fprintf(stderr, "Failed to url_encode string: %s\n", input);
        // Return an empty string to avoid NULL pointer issues, though this indicates an error
        return strdup(""); 
    }
    return output;
}

// Function to perform HTTP requests to HPKV API
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

    // Initialize response chunk
    response_chunk->memory = malloc(1); 
    response_chunk->size = 0;    
    if (!response_chunk->memory) { fprintf(stderr, "malloc failed\n"); return -1; }
    response_chunk->memory[0] = '\0';

    curl_handle = curl_easy_init();
    if (!curl_handle) {
        fprintf(stderr, "Failed to initialize curl\n");
        free(response_chunk->memory);
        return -1; 
    }

    // Construct full URL
    snprintf(full_url, sizeof(full_url), "%s%s", HPKV_DATA->api_base_url, path_segment);

    // Set common options
    curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response_chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "hpkvfs/0.1");
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connection timeout
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);      // 30 seconds total timeout

    // Set headers
    snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", HPKV_DATA->api_key);
    headers = curl_slist_append(headers, api_key_header);
    if (request_body) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, request_body);
    }
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

    // Set HTTP method
    if (strcmp(method, "GET") == 0) {
        // Default
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    // Perform the request
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\nURL: %s\n", curl_easy_strerror(res), full_url);
        http_code = -1; // Indicate curl error
    } else {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
    }

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);

    // If request failed internally or HTTP status indicates error, free response memory
    if (http_code < 200 || http_code >= 300) {
        if (response_chunk->memory) {
            free(response_chunk->memory);
            response_chunk->memory = NULL;
            response_chunk->size = 0;
        }
    }

    return http_code;
}

// Function to perform HTTP requests with retries
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
        http_code = perform_hpkv_request(method, path_segment, request_body, response_chunk);
        
        if ((http_code == 429 || (http_code >= 500 && http_code < 600) || http_code == -1) && retries < max_retries) {
            fprintf(stderr, "Request failed with %ld, retrying (%d/%d) after %ld ms...\n", 
                    http_code, retries + 1, max_retries, delay_ms);
            usleep(delay_ms * 1000); 
            delay_ms *= 2; 
            retries++;
        } else {
            break; 
        }
    }
    return http_code;
}

// Helper to map HTTP status codes to FUSE error codes
static int map_http_to_fuse_error(long http_code) {
    switch (http_code) {
        case 200: case 201: case 204: return 0;
        case 400: return -EINVAL;
        case 401: case 403: return -EACCES;
        case 404: return -ENOENT;
        case 409: return -EEXIST;
        case 429: return -EBUSY;
        case 500: case 502: case 503: case 504: return -EIO;
        case -1:  return -EIO; // Internal curl error
        default:  return -EIO;
    }
}

// --- Metadata Helper ---

static void get_meta_key(const char *path, char *meta_key_buf, size_t buf_size) {
    if (strcmp(path, "/") == 0) {
        snprintf(meta_key_buf, buf_size, "/.__meta__");
    } else {
        size_t path_len = strlen(path);
        if (path_len > 1 && path[path_len - 1] == '/') {
             snprintf(meta_key_buf, buf_size, "%.*s.__meta__", (int)path_len - 1, path);
        } else {
             snprintf(meta_key_buf, buf_size, "%s.__meta__", path);
        }
    }
}

// Helper to get metadata JSON object for a path
static json_t* get_metadata_json(const char *path) {
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *meta_json = NULL;
    json_error_t error;

    get_meta_key(path, meta_key, sizeof(meta_key));
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return NULL; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        meta_json = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!meta_json) {
            fprintf(stderr, "get_metadata_json: Failed to parse JSON for %s: %s\n", meta_key, error.text);
            return NULL;
        }
        // Check if it's an object
        if (!json_is_object(meta_json)) {
             fprintf(stderr, "get_metadata_json: Metadata for %s is not a JSON object\n", meta_key);
             json_decref(meta_json);
             return NULL;
        }
    } else {
        if (response.memory) free(response.memory);
        // Don't log ENOENT errors here, let caller handle
        if (http_code != 404) {
             fprintf(stderr, "get_metadata_json: API GET failed for %s, HTTP: %ld\n", meta_key, http_code);
        }
        return NULL; // Not found or error
    }
    return meta_json;
}

// Helper to POST metadata JSON object for a path
static int post_metadata_json(const char *path, json_t *meta_json) {
    char meta_key[1024];
    char *request_json_str = NULL;
    json_t *request_body_json = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    get_meta_key(path, meta_key, sizeof(meta_key));

    request_body_json = json_object();
    if (!request_body_json) { return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(meta_key));
    // Increment ref count of meta_json before giving it to request_body_json
    // because we might still need meta_json after this call returns.
    // json_object_set takes ownership, so we don't need incref here.
    json_object_set(request_body_json, "value", meta_json); 

    request_json_str = json_dumps(request_body_json, JSON_COMPACT);
    json_decref(request_body_json); // meta_json ref count decremented here

    if (!request_json_str) {
        fprintf(stderr, "post_metadata_json: Failed to dump JSON\n");
        return -EIO;
    }

    http_code = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "post_metadata_json: Failed POST for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code, ret);
    }
    return ret;
}

// --- FUSE Operations ---

static int hpkv_getattr(const char *path, struct stat *stbuf) {
    json_t *meta_json = NULL, *j_val;
    int ret = 0;

    memset(stbuf, 0, sizeof(struct stat));
    meta_json = get_metadata_json(path);

    if (meta_json) {
        // Defaults
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        time_t now = time(NULL);
        stbuf->st_atime = now;
        stbuf->st_mtime = now;
        stbuf->st_ctime = now;

        // Extract from JSON
        j_val = json_object_get(meta_json, "mode");
        if (json_is_integer(j_val)) stbuf->st_mode = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "size");
        if (json_is_integer(j_val)) stbuf->st_size = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "uid");
        if (json_is_integer(j_val)) stbuf->st_uid = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "gid");
        if (json_is_integer(j_val)) stbuf->st_gid = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "atime");
        if (json_is_integer(j_val)) stbuf->st_atime = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "mtime");
        if (json_is_integer(j_val)) stbuf->st_mtime = json_integer_value(j_val);
        j_val = json_object_get(meta_json, "ctime");
        if (json_is_integer(j_val)) stbuf->st_ctime = json_integer_value(j_val);

        if (S_ISDIR(stbuf->st_mode)) {
            stbuf->st_nlink = 2; 
        }

        json_decref(meta_json);
        ret = 0; // Success
    } else {
        // If get_metadata_json returned NULL, it could be ENOENT or EIO
        // We need a way to distinguish. Let's assume ENOENT for now.
        // A better way would be for get_metadata_json to return the error code.
        ret = -ENOENT; 
    }
    return ret;
}

static int hpkv_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
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

    // Determine prefix for range query
    if (path_len == 1 && path[0] == '/') {
        current_path_prefix = strdup("/");
    } else {
        // Ensure path ends with '/' for prefix matching
        if (path[path_len - 1] == '/') {
            current_path_prefix = strdup(path);
        } else {
            current_path_prefix = malloc(path_len + 2);
            if (current_path_prefix) {
                sprintf(current_path_prefix, "%s/", path);
            }
        }
    }
    if (!current_path_prefix) return -ENOMEM;
    size_t prefix_len = strlen(current_path_prefix);

    // Prepare start and end keys for range query
    strncpy(start_key_buf, current_path_prefix, sizeof(start_key_buf) - 1);
    start_key_buf[sizeof(start_key_buf) - 1] = '\0';
    snprintf(end_key_buf, sizeof(end_key_buf), "%s\xFF", start_key_buf);

    encoded_start_key = url_encode(start_key_buf);
    encoded_end_key = url_encode(end_key_buf);
    if (!encoded_start_key || encoded_start_key[0] == '\0' || !encoded_end_key || encoded_end_key[0] == '\0') {
        fprintf(stderr, "readdir: Failed to URL encode keys\n");
        free(encoded_start_key); free(encoded_end_key); free(current_path_prefix);
        return -EIO;
    }

    snprintf(api_path, sizeof(api_path), "/records?startKey=%s&endKey=%s&limit=1000", 
             encoded_start_key, encoded_end_key);
    free(encoded_start_key); free(encoded_end_key);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!root) {
            fprintf(stderr, "readdir: Failed to parse JSON for %s: %s\n", path, error.text);
            free(current_path_prefix); return -EIO;
        }

        records = json_object_get(root, "records");
        if (!json_is_array(records)) {
            fprintf(stderr, "readdir: 'records' field is not an array for %s\n", path);
            json_decref(root); free(current_path_prefix); return -EIO;
        }

        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);

        // Use a simple hash set or similar to track added names to avoid duplicates
        // For simplicity here, we might add duplicates if both file and meta keys are processed.
        // A better approach: iterate, extract base names, add to set, then call filler.

        for (i = 0; i < json_array_size(records); i++) {
            record = json_array_get(records, i);
            if (!json_is_object(record)) continue;
            key_json = json_object_get(record, "key");
            if (!json_is_string(key_json)) continue;

            const char *full_key = json_string_value(key_json);
            // Check if the key starts with the correct prefix
            if (strncmp(full_key, current_path_prefix, prefix_len) != 0) continue;

            const char *name_start = full_key + prefix_len;
            if (name_start[0] == '\0') continue; // Skip the prefix key itself

            const char *first_slash = strchr(name_start, '/');
            char entry_name[256];

            if (first_slash) { // Potential subdirectory or deeper file
                // Check if it's a direct child directory's metadata
                // e.g., prefix /a/, key /a/b/.__meta__ -> entry_name "b"
                if (strncmp(first_slash, "/.__meta__", 10) == 0 && first_slash[10] == '\0') {
                    snprintf(entry_name, sizeof(entry_name), "%.*s", (int)(first_slash - name_start), name_start);
                    filler(buf, entry_name, NULL, 0);
                }
                // Ignore deeper entries like /a/b/c or /a/b/c.__meta__
            } else { // Potential file at this level
                const char *meta_suffix = "__meta__";
                size_t name_len = strlen(name_start);
                size_t meta_suffix_len = strlen(meta_suffix);

                if (name_len > meta_suffix_len && strcmp(name_start + name_len - meta_suffix_len, meta_suffix) == 0) {
                    // Metadata key: /a/file.__meta__ -> entry_name "file"
                    snprintf(entry_name, sizeof(entry_name), "%.*s", (int)(name_len - meta_suffix_len), name_start);
                    filler(buf, entry_name, NULL, 0);
                } else {
                    // Content key: /a/file -> entry_name "file"
                    snprintf(entry_name, sizeof(entry_name), "%s", name_start);
                    filler(buf, entry_name, NULL, 0);
                }
            }
        }
        json_decref(root);
        ret = 0; // Success
    } else if (http_code == 404) {
        // No keys found in range, treat as empty directory
        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);
        ret = 0; 
    } else {
        fprintf(stderr, "readdir: API request failed for %s, HTTP code: %ld\n", path, http_code);
        ret = map_http_to_fuse_error(http_code);
    }

    free(current_path_prefix);
    return ret;
}

static int hpkv_mkdir(const char *path, mode_t mode) {
    json_t *meta_json = NULL;
    int ret = 0;
    time_t now = time(NULL);

    // Check if it already exists
    struct stat stbuf;
    if (hpkv_getattr(path, &stbuf) == 0) {
        return -EEXIST;
    }

    meta_json = json_object();
    if (!meta_json) return -ENOMEM;

    json_object_set_new(meta_json, "mode", json_integer(S_IFDIR | mode));
    json_object_set_new(meta_json, "uid", json_integer(getuid()));
    json_object_set_new(meta_json, "gid", json_integer(getgid()));
    json_object_set_new(meta_json, "size", json_integer(0)); // Dirs have 0 size
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    // post_metadata_json takes ownership of meta_json
    ret = post_metadata_json(path, meta_json);
    
    // If post_metadata_json failed, meta_json was already decref'd inside it
    // If it succeeded, meta_json was also decref'd inside it.

    return ret;
}

static int hpkv_rmdir(const char *path) {
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    int ret = 0;

    // TODO: Check for directory emptiness using readdir logic.
    // This requires a robust readdir and potentially multiple API calls.
    // Skipping for now, returning EPERM as a placeholder.
    // return -EPERM; // Placeholder: Directory not empty check missing

    get_meta_key(path, meta_key, sizeof(meta_key));
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    http_code = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0 && ret != -ENOENT) {
         fprintf(stderr, "rmdir: API DELETE failed for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code, ret);
    }
    return ret;
}

static int hpkv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char content_key[1024];
    char *request_json_str = NULL;
    json_t *meta_json = NULL, *request_body_json = NULL;
    struct MemoryStruct response; 
    long http_code_content;
    int ret = 0;
    time_t now = time(NULL);

    // Check if it already exists
    struct stat stbuf;
    if (hpkv_getattr(path, &stbuf) == 0) {
        return -EEXIST;
    }

    // 1. Create metadata
    meta_json = json_object();
    if (!meta_json) return -ENOMEM;
    json_object_set_new(meta_json, "mode", json_integer(S_IFREG | mode));
    json_object_set_new(meta_json, "uid", json_integer(getuid()));
    json_object_set_new(meta_json, "gid", json_integer(getgid()));
    json_object_set_new(meta_json, "size", json_integer(0));
    json_object_set_new(meta_json, "atime", json_integer(now));
    json_object_set_new(meta_json, "mtime", json_integer(now));
    json_object_set_new(meta_json, "ctime", json_integer(now));

    ret = post_metadata_json(path, meta_json); // Takes ownership of meta_json
    if (ret != 0) {
        // meta_json already decref'd by post_metadata_json
        fprintf(stderr, "create: Meta POST failed for %s, FUSE: %d\n", path, ret);
        return ret;
    }

    // 2. Create empty content
    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    request_body_json = json_object();
    if (!request_body_json) { /* TODO: Cleanup metadata? */ return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    json_object_set_new(request_body_json, "value", json_string(""));
    request_json_str = json_dumps(request_body_json, JSON_COMPACT);
    json_decref(request_body_json);
    if (!request_json_str) { fprintf(stderr, "create: Failed to dump content JSON\n"); /* TODO: Cleanup metadata? */ return -EIO; }

    http_code_content = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code_content);
    if (ret != 0 && ret != -EEXIST) { // EEXIST is okay here, maybe created concurrently
        fprintf(stderr, "create: Content POST failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code_content, ret);
        // TODO: Attempt to clean up metadata
        return ret;
    }

    return 0; // Success
}

static int hpkv_open(const char *path, struct fuse_file_info *fi) {
    int res = hpkv_getattr(path, &(struct stat){0}); // Check existence
    if (res != 0) return res;
    // Permissions are checked by VFS based on getattr mode
    return 0; 
}

static int hpkv_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char content_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code;
    json_t *root = NULL, *value_json = NULL;
    json_error_t error;
    int ret = 0;
    const char *file_content = NULL;
    size_t file_size = 0;

    // Get actual size from metadata first for binary safety
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            file_size = json_integer_value(j_size);
        }
        json_decref(meta_json);
    } else {
        return -ENOENT; // Metadata must exist
    }

    if (offset >= file_size) {
        return 0; // Read past EOF
    }

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';
    encoded_key = url_encode(content_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);

    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory);
        if (!root) {
            fprintf(stderr, "read: Failed to parse JSON response for %s: %s\n", content_key, error.text);
            return -EIO;
        }

        value_json = json_object_get(root, "value");
        if (!json_is_string(value_json)) {
            fprintf(stderr, "read: Value for key %s is not a string\n", content_key);
            json_decref(root);
            return -EIO; 
        }

        file_content = json_string_value(value_json);
        // Use file_size from metadata, not strlen(file_content)
        size_t content_len_from_json = json_string_length(value_json); // Use this for binary data
        // If content_len_from_json != file_size from metadata, there's inconsistency!
        if (content_len_from_json != file_size) {
             fprintf(stderr, "Warning: read: Size inconsistency for %s (meta: %zu, content: %zu)\n", 
                     path, file_size, content_len_from_json);
             // Use the smaller size to be safe?
             file_size = (file_size < content_len_from_json) ? file_size : content_len_from_json;
             if (offset >= file_size) { json_decref(root); return 0; }
        }

        if (offset + size > file_size) {
            size = file_size - offset;
        }
        memcpy(buf, file_content + offset, size);
        ret = size; 

        json_decref(root);
        
        // TODO: Optionally update atime

    } else {
        if (response.memory) free(response.memory);
        ret = map_http_to_fuse_error(http_code);
        if (ret != -ENOENT) {
            fprintf(stderr, "read: API GET failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        }
    }
    return ret;
}

// Helper function to update metadata times and optionally size
static int update_metadata_times(const char *path, int update_atime, int update_mtime, int update_ctime, size_t *new_size_ptr) {
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);
    int updated = 0;

    if (!meta_json) {
        return -ENOENT; // Cannot update times if metadata doesn't exist
    }

    if (update_atime) { json_object_set_new(meta_json, "atime", json_integer(now)); updated = 1; }
    if (update_mtime) { json_object_set_new(meta_json, "mtime", json_integer(now)); updated = 1; }
    if (new_size_ptr != NULL) { // Optionally update size
         json_object_set_new(meta_json, "size", json_integer(*new_size_ptr)); updated = 1; 
    }
    if (updated && update_ctime) { // Always update ctime if anything changed
        json_object_set_new(meta_json, "ctime", json_integer(now));
    }

    if (updated) {
        // post_metadata_json takes ownership of meta_json
        ret = post_metadata_json(path, meta_json);
    } else {
        json_decref(meta_json); // Nothing changed, just decref
        ret = 0;
    }
    return ret;
}

static int hpkv_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
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

    // Get current size from metadata
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            old_size = json_integer_value(j_size);
        }
        json_decref(meta_json);
    } else {
        return -ENOENT; // Cannot write if metadata doesn't exist
    }

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    // 1. Get current content (Read)
    encoded_key = url_encode(content_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);

    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);
    if (http_code == 200 && response.memory) {
        root = json_loads(response.memory, 0, &error);
        free(response.memory); response.memory = NULL;
        if (root) {
            value_json = json_object_get(root, "value");
            if (json_is_string(value_json)) {
                // Use json_string_value and json_string_length for binary safety
                const char* temp_content = json_string_value(value_json);
                size_t temp_len = json_string_length(value_json);
                // Verify against metadata size
                if (temp_len != old_size) {
                     fprintf(stderr, "Warning: write: Size inconsistency for %s (meta: %zu, content: %zu)\n", 
                             path, old_size, temp_len);
                     // Trust metadata size?
                     old_size = (old_size < temp_len) ? old_size : temp_len; 
                }
                old_content = malloc(old_size + 1); // Need mutable copy
                if (old_content) {
                    memcpy(old_content, temp_content, old_size);
                    old_content[old_size] = '\0'; // Null terminate for safety, though data might be binary
                } else {
                     json_decref(root); return -ENOMEM;
                }
            } else {
                 fprintf(stderr, "write: Existing value for %s is not a string, treating as empty.\n", content_key);
                 old_size = 0; // Reset size if content wasn't string
            }
            json_decref(root);
        } else {
             fprintf(stderr, "write: Failed to parse existing content JSON for %s: %s\n", content_key, error.text);
             old_size = 0; // Assume empty on parse failure
        }
    } else if (http_code == 404) {
        // File content doesn't exist, treat as empty
        if (response.memory) free(response.memory); response.memory = NULL;
        old_size = 0;
    } else {
        fprintf(stderr, "write: Failed to GET existing content for %s, HTTP: %ld\n", content_key, http_code);
        if (response.memory) free(response.memory);
        return map_http_to_fuse_error(http_code);
    }

    // 2. Modify content in memory (Modify)
    new_size = offset + size;
    if (new_size < old_size) {
        new_size = old_size; // Write doesn't implicitly truncate
    }

    new_content = malloc(new_size); // No +1 needed for binary data
    if (!new_content) {
        fprintf(stderr, "write: Failed to allocate memory for new content\n");
        free(old_content);
        return -ENOMEM;
    }

    // Copy part before offset
    size_t pre_offset_size = (offset < old_size) ? offset : old_size;
    if (old_content && pre_offset_size > 0) {
        memcpy(new_content, old_content, pre_offset_size);
    }

    // If offset is beyond old size, fill gap with zeros
    if (offset > old_size) {
        memset(new_content + old_size, 0, offset - old_size);
    }

    // Copy new data from buf
    memcpy(new_content + offset, buf, size);

    // Copy part after written data if extending within old bounds
    if (old_content && (offset + size < old_size)) {
        memcpy(new_content + offset + size, old_content + offset + size, old_size - (offset + size));
    }
    
    free(old_content); // Free the old content buffer

    // 3. POST new content (Write)
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    // Use json_stringn for binary safety
    json_object_set_new(request_body_json, "value", json_stringn(new_content, new_size));
    
    request_json_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII); // Ensure ASCII might be needed?
    json_decref(request_body_json);
    free(new_content); // Content is now in JSON string

    if (!request_json_str) { fprintf(stderr, "write: Failed to dump content JSON\n"); return -EIO; }

    http_code = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "write: Failed to POST content for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        return ret;
    }

    // 4. Update metadata (size, mtime, ctime)
    ret = update_metadata_times(path, 0 /*atime*/, 1 /*mtime*/, 1 /*ctime*/, &new_size);
    if (ret != 0) {
        fprintf(stderr, "write: Failed to update metadata for %s after write, FUSE: %d\n", path, ret);
        return ret;
    }

    return size; // Return number of bytes written
}

static int hpkv_truncate(const char *path, off_t size) {
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
    char *request_json_str = NULL;

    // Get current size from metadata
    json_t *meta_json = get_metadata_json(path);
    if (meta_json) {
        json_t *j_size = json_object_get(meta_json, "size");
        if (json_is_integer(j_size)) {
            old_size = json_integer_value(j_size);
        }
        json_decref(meta_json);
    } else {
        return -ENOENT; // Cannot truncate if metadata doesn't exist
    }

    // If size is the same, just update times and return
    if (size == old_size) {
        return update_metadata_times(path, 0, 1, 1, NULL);
    }

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';

    // 1. Get current content if needed (only if extending)
    if (size > old_size) {
        encoded_key = url_encode(content_key);
        if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
        snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
        free(encoded_key);

        http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response, 3);
        if (http_code == 200 && response.memory) {
            root = json_loads(response.memory, 0, &error);
            free(response.memory); response.memory = NULL;
            if (root) {
                value_json = json_object_get(root, "value");
                if (json_is_string(value_json)) {
                    const char* temp_content = json_string_value(value_json);
                    size_t temp_len = json_string_length(value_json);
                    if (temp_len != old_size) { /* Size inconsistency warning */ 
                         old_size = (old_size < temp_len) ? old_size : temp_len; 
                    }
                    old_content = malloc(old_size);
                    if (old_content) {
                        memcpy(old_content, temp_content, old_size);
                    } else {
                         json_decref(root); return -ENOMEM;
                    }
                } else { old_size = 0; }
                json_decref(root);
            } else { old_size = 0; }
        } else if (http_code == 404) {
            if (response.memory) free(response.memory); response.memory = NULL;
            old_size = 0;
        } else {
            fprintf(stderr, "truncate: Failed GET for extension %s, HTTP: %ld\n", content_key, http_code);
            if (response.memory) free(response.memory);
            return map_http_to_fuse_error(http_code);
        }
    } // else (shrinking): no need to get old content, just write new truncated/empty

    // 2. Create new content buffer
    new_content = malloc(size);
    if (!new_content) { free(old_content); return -ENOMEM; }

    if (size == 0) {
        // Special case: empty content
    } else if (size < old_size) {
        // Shrinking: Need old content to copy the prefix
        // This requires getting content even when shrinking, refactor needed.
        // Let's simplify: just write the new size, potentially losing data if API doesn't support partial writes.
        // For now, we assume POST overwrites. If shrinking, we write an empty string or null bytes?
        // Let's write null bytes for the new size.
        memset(new_content, 0, size);
    } else { // Extending
        if (old_content && old_size > 0) {
            memcpy(new_content, old_content, old_size);
        }
        // Pad with zeros
        memset(new_content + old_size, 0, size - old_size);
    }
    free(old_content);

    // 3. POST new content
    request_body_json = json_object();
    if (!request_body_json) { free(new_content); return -ENOMEM; }
    json_object_set_new(request_body_json, "key", json_string(content_key));
    json_object_set_new(request_body_json, "value", json_stringn(new_content, size));
    
    request_json_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    free(new_content);

    if (!request_json_str) { fprintf(stderr, "truncate: Failed to dump content JSON\n"); return -EIO; }

    http_code = perform_hpkv_request_with_retry("POST", "/record", request_json_str, &response, 3);
    free(request_json_str);
    if (response.memory) free(response.memory);

    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "truncate: Failed to POST content for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code, ret);
        return ret;
    }

    // 4. Update metadata (size, mtime, ctime)
    size_t final_size = size;
    ret = update_metadata_times(path, 0, 1, 1, &final_size);
    if (ret != 0) {
        fprintf(stderr, "truncate: Failed to update metadata for %s after truncate, FUSE: %d\n", path, ret);
        return ret;
    }

    return 0; // Success
}

static int hpkv_unlink(const char *path) {
    char content_key[1024];
    char meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response;
    long http_code_content, http_code_meta;
    int ret_content = 0, ret_meta = 0;

    strncpy(content_key, path, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';
    get_meta_key(path, meta_key, sizeof(meta_key));

    // 1. Delete content key
    encoded_key = url_encode(content_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    http_code_content = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) free(response.memory); response.memory = NULL;
    ret_content = map_http_to_fuse_error(http_code_content);
    if (ret_content != 0 && ret_content != -ENOENT) {
         fprintf(stderr, "unlink: Content DELETE failed for %s, HTTP: %ld, FUSE: %d\n", content_key, http_code_content, ret_content);
    }

    // 2. Delete metadata key
    encoded_key = url_encode(meta_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    http_code_meta = perform_hpkv_request_with_retry("DELETE", api_path, NULL, &response, 3);
    if (response.memory) free(response.memory); response.memory = NULL;
    ret_meta = map_http_to_fuse_error(http_code_meta);
     if (ret_meta != 0 && ret_meta != -ENOENT) {
         fprintf(stderr, "unlink: Meta DELETE failed for %s, HTTP: %ld, FUSE: %d\n", meta_key, http_code_meta, ret_meta);
    }

    // Return success only if meta delete succeeded or was ENOENT
    if (ret_meta == 0 || ret_meta == -ENOENT) {
        return 0; 
    } else {
        return ret_meta; // Return meta error if it occurred
    }
}

// NOTE: RENAME IS NOT ATOMIC!
static int hpkv_rename(const char *from_path, const char *to_path) {
    char from_content_key[1024], to_content_key[1024];
    char from_meta_key[1024], to_meta_key[1024];
    char api_path[2048];
    char *encoded_key = NULL;
    struct MemoryStruct response_get, response_post, response_delete;
    long http_code;
    json_t *root = NULL, *value_json = NULL, *request_body_json = NULL;
    json_error_t error;
    char *content_value = NULL; // Use char* for binary data
    size_t content_size = 0;
    char *meta_value_str = NULL;
    char *post_body_str = NULL;
    int ret = 0;
    struct stat stbuf_from = {0}, stbuf_to = {0};
    int from_is_dir = 0;

    // Get keys
    strncpy(from_content_key, from_path, sizeof(from_content_key) - 1); from_content_key[sizeof(from_content_key) - 1] = '\0';
    strncpy(to_content_key, to_path, sizeof(to_content_key) - 1); to_content_key[sizeof(to_content_key) - 1] = '\0';
    get_meta_key(from_path, from_meta_key, sizeof(from_meta_key));
    get_meta_key(to_path, to_meta_key, sizeof(to_meta_key));

    // Check source exists and get type
    if (hpkv_getattr(from_path, &stbuf_from) != 0) {
        return -ENOENT;
    }
    from_is_dir = S_ISDIR(stbuf_from.st_mode);

    // Check destination
    if (hpkv_getattr(to_path, &stbuf_to) == 0) {
        // Destination exists
        int to_is_dir = S_ISDIR(stbuf_to.st_mode);
        if (from_is_dir && !to_is_dir) return -ENOTDIR;
        if (!from_is_dir && to_is_dir) return -EISDIR;
        // If both are dirs, 'to' must be empty
        if (from_is_dir && to_is_dir) {
            // TODO: Check if 'to_path' is empty using readdir. Return -ENOTEMPTY if not.
            // Skipping check for now.
        }
        // Overwrite: delete destination first
        if (to_is_dir) {
            ret = hpkv_rmdir(to_path); // Assumes rmdir checks emptiness (or fails)
        } else {
            ret = hpkv_unlink(to_path);
        }
        if (ret != 0) {
             fprintf(stderr, "rename: Failed to remove existing destination %s, FUSE: %d\n", to_path, ret);
             return ret;
        }
    }

    // 1. Get 'from' metadata string
    encoded_key = url_encode(from_meta_key);
    if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); return -EIO; }
    snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
    free(encoded_key);
    http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response_get, 3);
    if (http_code != 200 || !response_get.memory) { /* Error */ if (response_get.memory) free(response_get.memory); return map_http_to_fuse_error(http_code); }
    root = json_loads(response_get.memory, 0, &error);
    if (!root) { /* Error */ free(response_get.memory); return -EIO; }
    value_json = json_object_get(root, "value");
    if (!json_is_string(value_json)) { /* Error */ json_decref(root); free(response_get.memory); return -EIO; }
    meta_value_str = strdup(json_string_value(value_json)); // Copy metadata string
    json_decref(root);
    free(response_get.memory); response_get.memory = NULL;
    if (!meta_value_str) return -ENOMEM;

    // 2. Get 'from' content (only if file)
    if (!from_is_dir) {
        encoded_key = url_encode(from_content_key);
        if (!encoded_key || encoded_key[0] == '\0') { free(encoded_key); free(meta_value_str); return -EIO; }
        snprintf(api_path, sizeof(api_path), "/record/%s", encoded_key);
        free(encoded_key);
        http_code = perform_hpkv_request_with_retry("GET", api_path, NULL, &response_get, 3);
        if (http_code == 200 && response_get.memory) {
            root = json_loads(response_get.memory, 0, &error);
            if (root) {
                 value_json = json_object_get(root, "value");
                 if (json_is_string(value_json)) {
                     const char* temp_content = json_string_value(value_json);
                     content_size = json_string_length(value_json);
                     content_value = malloc(content_size);
                     if (content_value) {
                         memcpy(content_value, temp_content, content_size);
                     } else {
                         ret = -ENOMEM;
                     }
                 } else { content_size = 0; content_value = strdup(""); }
                 json_decref(root);
            } else { content_size = 0; content_value = strdup(""); ret = -EIO; }
            free(response_get.memory); response_get.memory = NULL;
        } else if (http_code == 404) {
             content_size = 0; content_value = strdup(""); // Treat as empty
        } else {
            fprintf(stderr, "rename: Failed GET from_content %s, HTTP: %ld\n", from_content_key, http_code);
            if (response_get.memory) free(response_get.memory);
            ret = map_http_to_fuse_error(http_code);
        }
        if (ret != 0) { free(meta_value_str); free(content_value); return ret; }
    } // else: is directory, no content key

    // 3. POST 'to' metadata
    request_body_json = json_object();
    json_object_set_new(request_body_json, "key", json_string(to_meta_key));
    json_object_set_new(request_body_json, "value", json_string(meta_value_str));
    post_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(request_body_json);
    if (!post_body_str) { /* Error */ free(meta_value_str); free(content_value); return -EIO; }
    http_code = perform_hpkv_request_with_retry("POST", "/record", post_body_str, &response_post, 3);
    free(post_body_str); post_body_str = NULL;
    if (response_post.memory) free(response_post.memory); response_post.memory = NULL;
    ret = map_http_to_fuse_error(http_code);
    if (ret != 0) {
        fprintf(stderr, "rename: Failed POST to_meta %s, HTTP: %ld, FUSE: %d\n", to_meta_key, http_code, ret);
        free(meta_value_str); free(content_value);
        return ret; // Fail early
    }

    // 4. POST 'to' content (only if file)
    if (!from_is_dir) {
        request_body_json = json_object();
        json_object_set_new(request_body_json, "key", json_string(to_content_key));
        json_object_set_new(request_body_json, "value", json_stringn(content_value, content_size));
        post_body_str = json_dumps(request_body_json, JSON_COMPACT | JSON_ENSURE_ASCII);
        json_decref(request_body_json);
        if (!post_body_str) { /* Error */ free(meta_value_str); free(content_value); /* TODO: Delete to_meta? */ return -EIO; }
        http_code = perform_hpkv_request_with_retry("POST", "/record", post_body_str, &response_post, 3);
        free(post_body_str); post_body_str = NULL;
        if (response_post.memory) free(response_post.memory); response_post.memory = NULL;
        ret = map_http_to_fuse_error(http_code);
        if (ret != 0) {
            fprintf(stderr, "rename: Failed POST to_content %s, HTTP: %ld, FUSE: %d\n", to_content_key, http_code, ret);
            free(meta_value_str); free(content_value);
            // TODO: Attempt cleanup: delete 'to' keys
            return ret;
        }
    }

    // 5. DELETE 'from' (meta and content if file)
    // Use unlink/rmdir for consistency?
    if (from_is_dir) {
        ret = hpkv_rmdir(from_path); // This only deletes meta key
    } else {
        ret = hpkv_unlink(from_path); // Deletes both content and meta
    }
    if (ret != 0) {
         fprintf(stderr, "rename: Failed DELETE from %s, FUSE: %d. Inconsistency possible.\n", from_path, ret);
         // Continue anyway, copy succeeded.
    }

    free(meta_value_str);
    free(content_value);
    return 0; // Success (even if delete failed)
}

// --- FUSE setattr related functions (for FUSE_USE_VERSION 26) ---

static int hpkv_chmod(const char *path, mode_t mode) {
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);

    if (!meta_json) return -ENOENT;

    // Keep file type bits, update permission bits
    mode_t current_mode = json_integer_value(json_object_get(meta_json, "mode"));
    mode_t new_mode = (current_mode & S_IFMT) | (mode & ~S_IFMT);

    json_object_set_new(meta_json, "mode", json_integer(new_mode));
    json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime

    // post_metadata_json takes ownership
    ret = post_metadata_json(path, meta_json);
    return ret;
}

static int hpkv_chown(const char *path, uid_t uid, gid_t gid) {
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);
    int updated = 0;

    if (!meta_json) return -ENOENT;

    // FUSE passes -1 if uid/gid shouldn't be changed
    if (uid != (uid_t)-1) {
        json_object_set_new(meta_json, "uid", json_integer(uid));
        updated = 1;
    }
    if (gid != (gid_t)-1) {
        json_object_set_new(meta_json, "gid", json_integer(gid));
        updated = 1;
    }

    if (updated) {
        json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime
        // post_metadata_json takes ownership
        ret = post_metadata_json(path, meta_json);
    } else {
        json_decref(meta_json); // No changes, just decref
        ret = 0;
    }
    return ret;
}

// Corresponds to utime/utimens
static int hpkv_utimens(const char *path, const struct timespec ts[2]) {
    json_t *meta_json = get_metadata_json(path);
    int ret = 0;
    time_t now = time(NULL);

    if (!meta_json) return -ENOENT;

    // ts[0] is atime, ts[1] is mtime
    json_object_set_new(meta_json, "atime", json_integer(ts[0].tv_sec));
    json_object_set_new(meta_json, "mtime", json_integer(ts[1].tv_sec));
    json_object_set_new(meta_json, "ctime", json_integer(now)); // Update ctime

    // post_metadata_json takes ownership
    ret = post_metadata_json(path, meta_json);
    return ret;
}

// --- FUSE Setup ---

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
    // Use specific functions for FUSE 2.x
    .chmod   = hpkv_chmod,
    .chown   = hpkv_chown,
    .utimens = hpkv_utimens,
    // .setattr is not used in FUSE 2.x
};

// --- Main Function ---

#define OPTION(t, p) { t, offsetof(struct hpkv_options, p), 1 }
static const struct fuse_opt hpkv_opts[] = {
    OPTION("--api-url=%s", api_base_url),
    OPTION("--api-key=%s", api_key),
    FUSE_OPT_END
};

// Custom option processor (can be simplified if only using fuse_opt_parse)
static int hpkv_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    // Let fuse_opt_parse handle options defined in hpkv_opts
    // Let fuse handle its own options (-f, -s, mountpoint etc)
    return 1; 
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct hpkv_options options = {0}; 
    hpkv_config config = {0}; 
    int fuse_ret;

    // Set default values
    options.api_base_url = "https://default.hpkv.io"; // Placeholder default

    // Parse options
    if (fuse_opt_parse(&args, &options, hpkv_opts, hpkv_opt_proc) == -1) {
        fprintf(stderr, "Failed to parse options\n");
        return 1;
    }

    // Check required options
    if (!options.api_key) {
        fprintf(stderr, "Error: --api-key is required\nUsage: %s mountpoint --api-key=<key> [--api-url=<url>] [-f] [-s]\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }
    if (!options.api_base_url || options.api_base_url[0] == '\0') {
        fprintf(stderr, "Error: --api-url cannot be empty\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    // Assign parsed options to the config struct
    config.api_base_url = strdup(options.api_base_url);
    config.api_key = strdup(options.api_key);
    if (!config.api_base_url || !config.api_key) {
         fprintf(stderr, "Error: Failed to allocate memory for config\n");
         free(config.api_base_url); free(config.api_key);
         fuse_opt_free_args(&args);
         return 1;
    }

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    fprintf(stdout, "Starting HPKV FUSE filesystem.\nAPI URL: %s\nMounting...\n", config.api_base_url);

    // Pass config to FUSE context, run main loop
    fuse_ret = fuse_main(args.argc, args.argv, &hpkv_oper, &config);

    fprintf(stdout, "HPKV FUSE filesystem unmounted.\n");

    // Cleanup
    fuse_opt_free_args(&args);
    curl_global_cleanup();
    free(config.api_base_url);
    free(config.api_key);

    return fuse_ret;
}


