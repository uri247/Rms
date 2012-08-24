//
//  CapiOnEay.cpp
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#include <memory>
#include <string>
#include <AssertMacros.h>
#include "CryptInterface.h"
#include "Crypt.h"
#include "CryptOnOpenSSL.h"
#include "CryptOnKeychain.h"

typedef ContextType<ossl_RsaKey> OpenSSLContext;
typedef ContextType<kchn_RsaKey> KeyChainContext;


template<class CTX>
bool CryptAcquireContext( HCRYPTPROV* phprov )
{
    CTX* pctx = new CTX( );
    HCRYPTPROV hprov = (HCRYPTPROV)pctx;
    *phprov = hprov;
    return true;
}

template<class CTX>
bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* phkey )
{    
    check(hprov);
    CTX* pctx = (CTX*)hprov;
        
    typename CTX::KeyType* pkey;    
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



//
// If only objective-C had the אemplates, these dispatch boilerplate wouldn't be necessary. These
// methods dispatch between the two instances of the Crypt templated functions.
//

bool CryptAcquireContextOssl( HCRYPTPROV* phprov ) {
    return CryptAcquireContext<OpenSSLContext>( phprov );
}

bool CryptAcquireContextKchn( HCRYPTPROV* phprov ) {
    return CryptAcquireContext<KeyChainContext>( phprov );
}


bool CryptImportKeyOssl( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* phkey ) {
    return CryptImportKey<OpenSSLContext>( hprov, pdata, dataLen, flags, phkey );
}

bool CryptImportKeyKchn( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* phkey ) {
    return CryptImportKey<KeyChainContext>( hprov, pdata, dataLen, flags, phkey );
}


