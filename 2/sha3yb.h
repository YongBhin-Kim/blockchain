#ifndef _SHA3_H_
#define _SHA3_H_


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>



#ifdef __cplusplus
extern "C" 
{
#endif
	   


int sha3_hash(uint8_t *output, int outLen, uint8_t *input, int inLen, int bitSize, int useSHAKE);

#else

#endif
