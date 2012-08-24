//  CapiOnEay.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__CapiOnEay__
#define __SecGames__CapiOnEay__

#include "windef.h"

#define CRYPT_USE_OSSL 1


#if CRYPT_USE_OSSL
#define CryptAcquireContext CryptAcquireContextOssl
#define CryptImportKey CryptImportKeyOssl
#define CryptDecrypt CryptDecryptOssl
#else
#define CryptAcquireContext CryptAcquireContextKchn
#define CryptImportKey CryptImportKeyKchk
#define CryptDecrypt CryptDecryptKchn
#endif


__EXTERN_C_ bool CryptAcquireContextOssl( HCRYPTPROV* phprov );
__EXTERN_C_ bool CryptAcquireContextKchn( HCRYPTPROV* phprov );

__EXTERN_C_ bool CryptImportKeyOssl( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* hkey );
__EXTERN_C_ bool CryptImportKeyKchn( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* hkey );

__EXTERN_C_ bool CryptDecryptOssl( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
__EXTERN_C_ bool CryptDecryptKchn( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    
#endif
