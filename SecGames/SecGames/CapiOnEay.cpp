//
//  CapiOnEay.cpp
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#include <memory>
#include <AssertMacros.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "CapiOnEay.h"
#include "EayP.h"


bool CryptAcquireContext( HCRYPTPROV* phprov )
{
    Context* pctx = new Context( );
    HCRYPTPROV hprov = (HCRYPTPROV)pctx;
    *phprov = hprov;
    return true;
}


bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* phkey )
{
    check(hprov);
    Context* pctx = (Context*)hprov;
    Key* pkey;
    
    pkey = pctx->importKey(pdata, dataLen, flags );
    
    *phkey = (HCRYPTKEY)pkey;
    
    return true;
}
    

bool CryptDecrypt( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    check(hkey);
    Key* pkey = (Key*)hkey;
    check( pkey->magic() == magic_Key );
    pkey->Decrypt(final, flags, pdata, pdataLen);
    return true;
}
