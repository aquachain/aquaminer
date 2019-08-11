#include "aqua.h"
#include "argon2/argon2.h"
#include "vendor/uint256.h"
#include <assert.h>
#include <time.h>


//#define ENDPOINT "http://aquacha.in:8888/0x75fdeee8535defa6de26f270a8e6399229dd17d2/1"
#define ENDPOINT "http://127.0.0.1:8543"
static const size_t INPUT_SIZE = 40;   // input for hash fn
static const size_t OUTPUT_BYTES = 32; // output for hashfn
static const unsigned int DEFAULT_ARGON2_FLAG = 2;
static const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5',
                                           '6', '7', '8', '9', 'A', 'B',
                                           'C', 'D', 'E', 'F'};

static const char *aqua_dummy_header =
    "0x7a4269757dd6419dd70b22b4e1e7a965fbda889982f8619be03bca16e49095c8";
static const char *aqua_dummy_target =
    "0x000060f7ac9c00f6f6cb9d5274fc8e94ae01f33b22ab2cf77a9c4bf6864c4610";

void convertUint256BE(uint8_t *data, uint32_t length, uint256_t *target) {
  uint8_t tmp[32];
  memset(tmp, 0, 32);
  memmove(tmp + 32 - length, data, length);
  readu256BE(tmp, target);
}

// Aquachain
int aquahash_v2(void *output, const void *input, uint32_t m_cost) {
  argon2_context context;
  context.out = (uint8_t *)output;
  context.outlen = (uint32_t)OUTPUT_BYTES;
  context.pwd = (uint8_t *)input;
  context.pwdlen = (uint32_t)INPUT_SIZE;
  context.salt = NULL;
  context.saltlen = 0;
  context.secret = NULL;
  context.secretlen = 0;
  context.ad = NULL;
  context.adlen = 0;
  context.allocate_cbk = NULL;
  context.free_cbk = NULL;
  context.flags = DEFAULT_ARGON2_FLAG;
  context.m_cost = m_cost;
  context.lanes = 1;
  context.threads = 1;
  context.t_cost = 1;
  context.version = ARGON2_VERSION_13;
  return argon2_ctx(&context, Argon2_id);
}

bool aquahash(char version, void *output, void *input) {
  uint8_t mem = 1;

  if (version == 2) {
    mem = 1;
  }
  if (version == 3) {
    mem = 16;
  }
  if (version == 4) {
    mem = 32;
  }
  return aquahash_v2(output, input, mem);
}

int char2int(char input) {
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
}

/* Adequate size s==len*2 + 1 must be alloced to use this variant */
void __bin2hex(char *s, const unsigned char *p, size_t len) {
  int i;
  static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (i = 0; i < (int)len; i++) {
    *s++ = hex[p[i] >> 4];
    *s++ = hex[p[i] & 0xF];
  }
  *s++ = '\0';
}

/* Returns a malloced array string of a binary value of arbitrary length. The
 * array is rounded up to a 4 byte size to appease architectures that need
 * aligned array  sizes */
char *bin2hex(const unsigned char *p, size_t len) {
  ssize_t slen;
  char *s;

  slen = len * 2 + 1;
  if (slen % 4)
    slen += 4 - (slen % 4);
  s = (char *)calloc(slen, 1);
  if (unlikely(!s))
    exit(111);
  __bin2hex(s, p, len);

  return s;
}

void hex2bin(const uint8_t *src, uint8_t *target) {
  while (*src && src[1]) {
    *(target++) = char2int(*src) * 16 + char2int(src[1]);
    src += 2;
  }
}

uint8_t getVersion(const char *aux) {
  uint8_t hversion = 0;
  if (aux[64] != '0') {
    return 0;
  }
  switch (aux[65]) {
  case '1':
    hversion = 1;
    break;
  case '2':
    hversion = 2;
    break;
  case '3':
    hversion = 3;
    break;
  case '4':
    hversion = 4;
    break;
  default:
    printf("could not find version from farm: %d %c", hversion, aux[65]);
    break;
  }
  return hversion;
}

bool get_work(work_t *currentWork) {
  if (currentWork == NULL || currentWork->target == NULL ||
      currentWork->header == NULL) {
    return false;
  }
  char *text = request(ENDPOINT);
  json_error_t error;
  json_t *root = json_loads(text, 0, &error);
  if (!text) {
    return false;
  }
  if (!json_is_object(root)) {
    printf("json decode error 1\n");
    json_decref(root);
    return false;
  }
  json_t *data = json_object_get(root, "result");

  // want string[3]
  if (!json_is_array(data)) {
    printf("error: %s\n", text);
    free(text);
    json_decref(root);
    return false;
  }
  if (json_array_size(data) != 3) {
    printf("json decode error\n");
    free(text);
    json_decref(root);
    return false;
  }

  // these include 0x
  const char *header = json_string_value(json_array_get(data, 0));
  const char *aux = json_string_value(json_array_get(data, 1));
  const char *target = json_string_value(json_array_get(data, 2));

  hex2bin((char *)header + 2, (char *)currentWork->header);
  hex2bin((char *)target + 2, (char *)currentWork->target);
  currentWork->version = getVersion(aux);
  json_decref(root);
  free(text);
  return true;
}

void print_work(work_t *work) {
  // print new work
  printf("hash=%s\n\ntarget=%s\nversion=%u\n",
         (unsigned char *)((work_t *)work)->header,
         (unsigned char *)((work_t *)work)->target, (uint8_t)(work->version));
  if (work->nonce != 0) {
    printf("nonce=%u\n", work->nonce);
  }
  fflush(stdout);
}

bool parse_diff(char *out, char *pooldiff) { return strcpy(out, pooldiff); }

static const char *submitfmt =
    "{\"jsonrpc\":\"2.0\", \"id\" : 42, \"method\" : \"aqua_submitWork\", "
    "\"params\" : "
    "[\"0x%s\",\"0x%s\","
    "\"0x0000000000000000000000000000000000000000000000000000000000000000\"]}";

double clockToMilliseconds(clock_t ticks) {
  // units/(units/time) => time (seconds) * 1000 = milliseconds
  return (ticks / (double)CLOCKS_PER_SEC) * 1000.0;
}

static int mine(work_t *work, int thr_id) {
  char *load = (char *)malloc(40 * sizeof(char));
  memcpy(load, work->header, 32);
  srand(time(NULL));
  char out[32];
  char *target_str = bin2hex(work->target, 32);

  load[32] = 0;
  load[33] = 0;
  load[34] = 0;
  load[34] = 0;
  load[35] = 0;
  load[36] = 0;
  load[37] = 0;
  load[38] = 0;
  for (int i = 32; i < 40; i++) {
    load[i] = rand() % 255;
  }
  char *loadstr = bin2hex(&(load[32]), 8);
  printf("nonce:  %s\n", loadstr);
  free(loadstr);
  loadstr = bin2hex(load, 40);
  printf("header= %s\ntarget= %s\nversion=%u\n", loadstr, target_str,
         (uint8_t)work->version);
  free(loadstr);

  clock_t start = clock();

  uint64_t start_nonce = (uint64_t)&load[32];
  printf("version = %d\n", work->version);
  printf("start_nonce=%u\n", start_nonce);

  uint256_t *bigtarget = (uint256_t *)malloc(sizeof bigtarget);

  convertUint256BE(work->target, 32, bigtarget);
  uint256_t *bignum = malloc(sizeof bignum);
  assert(bignum != 0);

  // hashrate
  clock_t deltaTime = 0;
  unsigned int frames = 0;
  double frameRate = 30;
  double averageFrameTimeMilliseconds = 33.333;

  // mining loop
  while (true) {
    clock_t beginFrame = clock();

    // increment nonce
    for (int i = 39; i > 32; i--) {
      load[i]++;
      if (load[i] != 0) {
        break;
      }
      load[i - 1]++;
      if (load[i - 1] != 0) {
        break;
      }
    }

#ifdef DEBUGIN
            // print input
      char *loadstr = bin2hex(load, 40);
      printf("load:%s\n", loadstr);
	  printf("header= %s\ntarget= %s\nversion=%u\n", loadstr, target_str,
         (uint8_t)work->version);
      free(loadstr);
#endif

    // hash
    int ret = aquahash(work->version, out, load);
    if (ret != ARGON2_OK) {
      printf("aquahash failed!\n");
      return -1;
    }

    // print stuff every second
    clock_t endFrame = clock();
    deltaTime += endFrame - beginFrame;
    frames++;
    if (clockToMilliseconds(deltaTime) > 1000.0) {        // every second
      frameRate = (double)frames * 0.5 + frameRate * 0.5; // more stable
      frames = 0;
      deltaTime -= CLOCKS_PER_SEC;
      averageFrameTimeMilliseconds =
          1000.0 / (frameRate == 0 ? 0.001 : frameRate);
      printf("hashtime %4.4f hashrate %4.4f\n", averageFrameTimeMilliseconds,
             frames);
    }

    // compare to target
    convertUint256BE(out, 32, bignum);
    // got it
    if (gt256(bigtarget, bignum)) {
      // if (false){
#ifdef DEBUG
      char *outstr = bin2hex(out, 32);
      printf("hashed=%s\n", outstr);
      free(outstr);
#endif

      // reverse nonce endianness (last 8 bytes)
      char revNonce[8];
      for (int i = 0; i < 8; i++) {
        revNonce[i] = load[39 - i];
      }
      char *noncehex = bin2hex((char *)revNonce, 8);

      // get hex of first 32 bytes
      char *origLoad = bin2hex(load, 32);
      char buf[233]; // submit packet always 232?

      // build request
      sprintf(buf, submitfmt, noncehex, origLoad);
      if (!submit_nonce(ENDPOINT, buf)) {
        printf("nonce bad?\n");
      } else {
		printf("nonce submitted\n");
	  }

      free(noncehex);
      free(origLoad);
      printf("getting new work in 800000us\n");
     usleep(800000);
      if (!get_work(work)) {
        printf("couldn't get work\n");
        assert(false);
        return -1;
      }
      printf("got new work\n");
    }
  }
}

void start_miner(work_t *work, int n_thread) {
  while (true) {
    if (-1 == mine(work, 1)) {
      break;
    }
  }
}

#ifdef RUN_TEST
int main(void) { return 0; }
#endif
