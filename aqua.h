#include "http.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ZEROS                                                                  \
  "0x0000000000000000000000000000000000000000000000000000000000000000"

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

const static int len32b_str = strlen(ZEROS);

char *bin2hex(const unsigned char *p, size_t len);

typedef struct work_t {
  uint8_t *header; // input for mining
  uint8_t *target; // difficulty
  uint64_t nonce;  // for submit
  uint8_t version; // hash version (1 = ethash, 2 = argon2id(1,1,1))
} work_t;

bool run(void); // defined in in foo.c

// defined in aqua.c
bool get_work(work_t *work);
bool submit_work(work_t *work);
int aqua_cmp_diff(void *b, void *b2);
bool parse_diff(char *target, char *destination);

void start_miner(work_t *work, int num_threads);
bool aquahash(char version, void *out, void *in);
