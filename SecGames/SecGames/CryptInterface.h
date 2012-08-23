//  CapiOnEay.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__CapiOnEay__
#define __SecGames__CapiOnEay__

#include "windef.h"


__EXTERN_C_ bool CryptAcquireContext( HCRYPTPROV* phprov );
__EXTERN_C_ bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* hkey );
__EXTERN_C_ bool CryptDecrypt( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    
    
#endif
