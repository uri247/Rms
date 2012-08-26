//
//  windef.h
//  SecGames
//
//  Created by Uri London on 8/21/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef SecGames_windef_h
#define SecGames_windef_h

#include <stddef.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int ALG_ID;


typedef unsigned long HANDLE;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTKEY;



typedef struct _PUBLICKEYSTRUC {
    BYTE    bType;
    BYTE    bVersion;
    WORD    reserved;
    ALG_ID  aiKeyAlg;
} BLOBHEADER;


typedef struct _RSAPUBKEY {
    DWORD   magic;                  // Has to be RSA1 or RSA2
    DWORD   bitlen;                 // # of bits in modulus
    DWORD   pubexp;                 // public exponent
    // Modulus data follows
} RSAPUBKEY;


#ifdef __cplusplus
#define __EXTERN_C_ extern "C"
#else
#define __EXTERN_C_
#endif


#endif
