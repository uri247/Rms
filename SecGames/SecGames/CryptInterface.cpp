// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   CryptInerface.cpp
//
// Synopsis:    This file contains tye IpcOsCryptXXX interfaces. These are C-sytle methods heavily inspired
//              by Win32 CAPI functions. This is a thin layer that delegates most of the work to the various
//              classes (CContext for provider context, CKey for encryption/decryption, CHash for hash, etc.)
//
//              The "root" funciton - CryptAcquireContext - is templetize. It may return various templates,
//              depends on the requirements. The context is a collection of provider classes using a different
//              platform. For example, the ossl_RsaKey provides Rsa functionality on top of OpenSSL while
//              kchn_RsaKey implements the same functionality on top of iOS securtiy Key Chain.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#include <memory>
#include <string>
#include <AssertMacros.h>
#include "CryptInterface.h"
#include "Crypt.h"
#include "CryptOnOpenSSL.h"
#include "CryptOnKeychain.h"


typedef ContextType<ossl_RsaKey, int, CRandom, int> OpenSSLContext;
typedef ContextType<kchn_RsaKey, int, CRandom, int> KeyChainContext;



template<class CTX>
bool CryptAcquireContext( HCRYPTPROV* phprov )
{
    CContext* pctx = new CTX( );    
    *phprov = CHandle::c2h( pctx );
    return true;
}

// Overcome an Object-C limitation of not having templates. These two functions are poor-language's
// "template instantiation" with specific arguments
bool CryptAcquireContextOssl( HCRYPTPROV* phprov )    { return CryptAcquireContext<OpenSSLContext>( phprov ); }
bool CryptAcquireContextKchn( HCRYPTPROV* phprov )    { return CryptAcquireContext<KeyChainContext>( phprov ); }



bool CryptContextAddRef( HCRYPTPROV hprov )
{
    CContext* pctx = CHandle::h2c<CContext>( hprov );
    pctx->addRef( );
    return true;
}

bool CryptReleaseContext( HCRYPTPROV hprov )
{
    CContext* pctx = CHandle::h2c<CContext>( hprov );
    pctx->release( );
    return true;
}

bool CryptImportKey( HCRYPTPROV hprov, BYTE* pdata, DWORD dataLen, DWORD flags, HCRYPTKEY* phkey )
{
    CContext* pctx = CHandle::h2c<CContext>( hprov );
    CKey* pkey = pctx->importKey(pdata, dataLen, flags);
    *phkey = CHandle::c2h( pkey );
    return true;
}


bool CryptDecrypt( HCRYPTKEY hkey, bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    check(hkey);
    CKey* pkey = CHandle::h2c<CKey>(hkey);
    pkey->Decrypt(final, flags, pdata, pdataLen);
    return true;
}


