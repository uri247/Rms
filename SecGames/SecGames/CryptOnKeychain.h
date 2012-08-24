//
//  CryptOnKeychain.h
//  SecGames
//
//  Created by Uri London on 8/23/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__CryptOnKeychain__
#define __SecGames__CryptOnKeychain__

#include <string>
#include "windef.h"
#include "Crypt.h"


class kchn_RsaKey : public Key
{
private:
    std::string m_tag;

public:
    kchn_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen );
    
    ~kchn_RsaKey( );


};


#endif /* defined(__SecGames__CryptOnKeychain__) */
