#include "http.h"
#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static size_t write_response(void *ptr, size_t size, size_t nmemb,
                             void *stream) {
  struct write_result *result = (struct write_result *)stream;
  if (result->pos + size * nmemb >= BUFFER_SIZE - 1) {
    fprintf(stderr, "error: too small buffer\n");
    return 0;
  }
  memcpy(result->data + result->pos, ptr, size * nmemb);
  result->pos += size * nmemb;
  return size * nmemb;
}
char *request(const char *url) {
  CURL *curl = NULL;
  CURLcode status;
  struct curl_slist *headers = NULL;
  char *data = NULL;
  long code;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if (!curl)
    goto error;

  data = malloc(BUFFER_SIZE);
  if (!data)
    goto error;

  struct write_result write_result = {.data = data, .pos = 0};

  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* GitHub commits API v3 requires a User-Agent header */
  headers = curl_slist_append(headers, "User-Agent: AquaMinerPro");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                   "{\"jsonrpc\":\"2.0\",\"method\":\"aqua_getWork\","
                   "\"params\":[],\"id\":42}");
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

  status = curl_easy_perform(curl);
  if (status != 0) {
    fprintf(stderr, "error: unable to request data from %s:\n", url);
    fprintf(stderr, "%s\n", curl_easy_strerror(status));
    goto error;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (code != 200) {
    fprintf(stderr, "error: server responded with code %ld\n", code);
    goto error;
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  curl_global_cleanup();

  /* zero-terminate the result */
  data[write_result.pos] = '\0';

  return data;

error:
  if (data)
    free(data);
  if (curl)
    curl_easy_cleanup(curl);
  if (headers)
    curl_slist_free_all(headers);
  curl_global_cleanup();
  return NULL;
}

bool submit_nonce(const char *url, const char *payload) {
  bool ret;
  CURL *curl = NULL;
  CURLcode status;
  struct curl_slist *headers = NULL;
  char *data = NULL;
  data = malloc(BUFFER_SIZE);
  if (!data) {
    goto error;
  }
  long code;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if (!curl)
    goto error;
  struct write_result write_result = {.data = data, .pos = 0};
  curl_easy_setopt(curl, CURLOPT_URL, url);
  headers = curl_slist_append(headers, "User-Agent: AquaMinerPro");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);
  // fprintf(stderr, "submitting: %s\n", payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
  status = curl_easy_perform(curl);
  if (status != 0) {
    fprintf(stderr, "error: unable to request data from %s:\n", url);
    fprintf(stderr, "%s\n", curl_easy_strerror(status));
    goto error;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (code != 200) {
    fprintf(stderr, "error: server responded with code %ld\n", code);
    goto error;
  }

  /* zero-terminate the result */
  data[write_result.pos] = '\0';

  json_error_t error;
 json_t *root = json_loads(data, 0, &error);
  if (!root) {
		  ret = false;
		  goto error;
  }
 if (!json_is_object(root)) {
    printf("json decode error 1\n");
    json_decref(root);
    return false;
  }
  json_t *good = json_object_get(root, "result");
  if (json_is_true(good)){
	ret = true;
  }


error:
  if (data)
    //	printf("[pool] %s\n", data);
    free(data);
  if (curl)
    curl_easy_cleanup(curl);
  if (headers)
    curl_slist_free_all(headers);
  curl_global_cleanup();
  return ret;
}
