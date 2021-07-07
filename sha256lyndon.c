/*
Author: Lyndon Li
Filename: sha256lyndon.c
Objective: SHA-256 implementation in C according to the documentation set out by NIST
References: https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
*/



#include <stdlib.h>
#include <cstdio>
#include <cstring>

//Section 3.2
typedef unsigned char BYTE;         // 8 bit Byte
typedef unsigned int  WORD;         //32 bit Word    
#define SHA256_BLOCK_SIZE 32 		//32 Byte Digest
typedef struct {
	BYTE data[64]; //first 64 bytes are used in data
	WORD datalen; //amount of data points
	unsigned long long bitlen; //amount of bits used in data
	WORD state[8]; // states a...h
} 
SHA256_CTX;


//rotation of bits considering 32 bits
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

//Section 4.1.2 functions
// x will become y or z depending on inputs
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
// result will be the majority of 1 or 0 for each word
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
//Epsilon and Sigma Functions
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

//Section 4.2.2 Constants
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};




//Section 6.2.2
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

//message schedule
	for (i = 0, j = 0; i < 16; ++i)
	{
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
		j += 4;
	}
	for ( i = 16; i < 64; ++i)
	{
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	}
//a...h are pointers to each state in ctx
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

//hash computations
	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
//state gets updated
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}
//initial condition of hash function
//Section 5.3.2
void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}
//adding data to ctx pointer
void sha256_update(SHA256_CTX *ctx, const BYTE data[])
{
	WORD i;

	for (i = 0; i < strlen((char *)data); ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {				//if data length greater than 64, stop adding data 
			sha256_transform(ctx, ctx->data);	//and transform
			ctx->bitlen += 512;					//known that max data has been used so no padding necessary; bit length is 512
			ctx->datalen = 0;
		}
	}
}
//Section 5.1.1
void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// after datalength, append 1 and continually add zeros until 56 bits reached
	if (ctx->datalen < 56) {
		ctx->data[i++] =0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	//if datalength is 56 or greater, take first 56 bits, append 1 to end
	//and continually add zeros
	else {			
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
	}

	// Padding end is 64 bit block with length in binary
	 // first 56 of the block is 00000000
	
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen; //last 8 bit block is length of data bits in binary representation
	ctx->data[62] = ctx->bitlen >> 8; //shifting bitlength to end of length block
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	//shifts bytes in the front to the back effectively reversing the order of the bytes
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0]) >> (24 - i * 8); 
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)); 
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)); 
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)); 
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)); 
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)); 
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)); 
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)); 
	}
	
}
int main()
{	
	BYTE text1[] = {"lyndon"};
	BYTE hash[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int i = 0;
	sha256_init(&ctx);
	sha256_update(&ctx, text1);
	sha256_final(&ctx, hash);

	
	while (i < sizeof(hash))
	{
		printf("%02X",(int)hash[i]);
     	++i;
	}
	printf("\n");
	return(0);
}
