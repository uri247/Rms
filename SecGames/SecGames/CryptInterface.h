//
// File Name:   CryptInerface.h
//
// Synopsis:    This file contains declerations of IpcOsCryptXXX interfaces. this is the cryptographic
//              functions used by RMS client. The API is heavily inpirsed by Win32 CAPI, with some
//              minor modifiction to reduce the interface.
//              Although implementation is in a CPP file (CryptInterface.cpp), the functionality can be
//              used in either C, CPP or Objective-C.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#ifndef __SecGames__CapiOnEay__
#define __SecGames__CapiOnEay__

#include "windef.h"

#define CRYPT_USE_OSSL 1


#if CRYPT_USE_OSSL
#define CryptAcquireContext CryptAcquireContextOssl
#else
#define CryptAcquireContext CryptAcquireContextKchn
#endif


__EXTERN_C_ bool CryptAcquireContextOssl( HCRYPTPROV* phprov );
__EXTERN_C_ bool CryptAcquireContextKchn( HCRYPTPROV* phprov );

__EXTERN_C_ bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* hkey );
__EXTERN_C_ bool CryptDecrypt( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
__EXTERN_C_ bool CryptContextAddRef( HCRYPTPROV hprov );
__EXTERN_C_ bool CryptReleaseContext( HCRYPTPROV hprov );


#endif
