//
//  windef.h
//  SecGames
//
//  Created by Uri London on 8/21/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef SecGames_windef_h
#define SecGames_windef_h


typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int ALG_ID;


typedef unsigned long HANDLE;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTKEY;

#ifdef __cplusplus
#define __EXTERN_C_ extern "C"
#else
#define __EXTERN_C_
#endif


#endif
