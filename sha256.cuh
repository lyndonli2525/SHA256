#ifndef SHA256_H
#define SHA256_H

#include <cuda.h>
#include <stddef.h>

typedef unsigned char BYTE;  // 8 bit Byte
typedef unsigned int WORD;   // 32 bit Word
#define SHA256_BLOCK_SIZE 32 // 32 Byte Digest
typedef struct {
  BYTE data[64];
  WORD datalen;
  unsigned long long bitlen;
  WORD state[8];
} SHA256_CTX;

typedef struct JOB {
  size_t size;
  BYTE digest[64];
  BYTE *data;
} JOB;

// Functions


void runJobs(JOB **jobs, int num_jobs);
__global__ void sha256_cuda(BYTE *data, int n, size_t len, BYTE *digest);
void pre_sha256();
__device__ void sha256_final(SHA256_CTX *ctx, BYTE hash[]);
__device__ void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
__device__ void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);
__device__ void sha256_init(SHA256_CTX *ctx);
void print_job(JOB **jobs, int num_jobs);
void init_data(BYTE *arr, BYTE const data[], size_t len);
void init_digest(BYTE *arr);
#endif // SHA256_H