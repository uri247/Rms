// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   CryptOnKeychain
//
// Synopsis:    Implementation of RsaKey interface on top of Apple's iOS Security Key Chain framework.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#ifndef __CryptOnKeychain_h_
#define __CryptOnKeychain_h_

#include <string>
#include "windef.h"
#include "Crypt.h"


class kchn_RsaKey : public CKey
{
private:
    std::string m_tag;

public:
    kchn_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen );
    
    ~kchn_RsaKey( );
};


class cc_AesKey : public CKey
{
private:
    std::string m_tag;
    std::unique_ptr<BYTE[]> m_key;
    int m_keylen;
    
public:
    cc_AesKey( BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD buflen );
};

#endif