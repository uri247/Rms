// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   CryptOnOpenSSL.h
//
// Synopsis:    Contains the definition of class ossl_RsaKey. this class uses OpenSSL library RSA object
//              to perform its operations
//
// Author:      Uri London (v-uril@microsoft.com)
//

#ifndef __CryptOnOpenSSL_h_
#define __CryptOnOpenSSL_h_

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "windef.h"
#include "Crypt.h"


class ossl_RsaKey : public CKey
{
private:
    RSA* m_eayRsa;
    
public:
    ossl_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen );
    
    ~ossl_RsaKey( );
};



#endif