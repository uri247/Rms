//
//  CryptOnOpenSSL.h
//  SecGames
//
//  Created by Uri London on 8/23/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__CryptOnOpenSSL__
#define __SecGames__CryptOnOpenSSL__

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "windef.h"
#include "Crypt.h"


class RsaKey : public Key
{
private:
    RSA* m_eayRsa;
    
public:
    RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen );
    
    ~RsaKey( );
};



#endif /* defined(__SecGames__CryptOnOpenSSL__) */
