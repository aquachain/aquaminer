#include "aqua.h"

void hex2bin(void *, void *);

void run2(void);
bool run(void) {
  bool ok = true;
  char out[32];
  char in[40];
  hex2bin("c39f1ffd0690431d90084674dc829382b5d0cfd6ad5d58ea9162b7d3fd72ae5ecc13"
          "f76f10ba84db",
          in);
  aquahash(2, out, in);
  char *outstr = bin2hex(out, 32);
  bool testpass = !strcmp(
      "0000000008c3f9d637e8378c833ec1b4b862b57a37749379fe68d8b88cad54f7",
      outstr);
  free(outstr);
  if (!testpass) {
    printf("test hash failed.\n");
    return false;
  }

  work_t *work;
  work = (work_t *)malloc(sizeof(work_t));
  work->target = (uint8_t *)malloc(32 * sizeof(uint8_t));
  work->header = (uint8_t *)malloc(40 * sizeof(uint8_t));
  ok = get_work(work);
  if (!ok) {
    printf("failed to getwork\n");
    goto finish_run;
  }
  ok = (work->header != NULL && work->target != NULL);
  if (!ok) {
    printf("%s is NULL!\n",
           work->header == NULL ? "work->header" : "work->target");
    goto finish_run;
  }

  // printf("[newWork] input_hash=%s\n", work->header[0]);
  // start N threads
  start_miner(work, 1);

finish_run:
  free(work->target);
  free(work->header);
  free(work);
  return ok;
}

#ifdef RUN_TEST
int main(void) { return 0; }
#endif
