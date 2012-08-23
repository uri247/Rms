//
//  CapiOnEay.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__CapiOnEay__
#define __SecGames__CapiOnEay__

#include "windef.h"

#ifdef __cplusplus
extern "C" {
#endif


bool CryptAcquireContext( HCRYPTPROV* phprov );
bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* hkey );
bool CryptDecrypt( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );


#ifdef __cplusplus
}
#endif
    
    


#endif /* defined(__SecGames__CapiOnEay__) */
