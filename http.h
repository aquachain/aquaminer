#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE (256 * 1024) /* 256 KB */
struct write_result {
  char *data;
  int pos;
};
static size_t write_response(void *ptr, size_t size, size_t nmemb,
                             void *stream);
bool submit_nonce_real(const char *url, const char *payload);
bool submit_nonce(const char *url, const char *payload);
void roll_nonces(const uint8_t version, const uint8_t *hash,
                 const uint8_t *target);
char *request(const char *url);

json_t *work_decode(json_t *);
