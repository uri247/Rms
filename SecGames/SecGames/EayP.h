//
//  Header.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef SecGames_Header_h
#define SecGames_Header_h

#include <openssl/evp.h>
#include <openssl/rsa.h>


// big endian magic
DWORD const magic_Context = ('C'<<24 | 'N'<<16 | 'T'<<8 | 'X');
DWORD const magic_Key = ('K'<<24 | 'K'<<16 | 'E'<<8 | 'Y');


class Context;
class Key;
class RsaKey;

class EayBase
{
private:
    DWORD m_magic;
    
protected:
    EayBase( DWORD magic ) : m_magic(magic) { }
    
public:
    DWORD magic() { return m_magic; }
};


class Context : public EayBase
{
public:
    Context( ) : EayBase(magic_Context) { }
    Key* importKey( BYTE* pdata, DWORD dataLen, DWORD flags );
};



class Key : public EayBase
{
public:
    Key( ) : EayBase(magic_Key) { }

public:
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen ) =0;
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen ) =0;

};


class RsaKey : public Key
{
private:
    RSA* m_eayRsa;
    Context* m_pctx;
    
public:
    RsaKey( Context* pctx, BYTE* pdata, DWORD dataLen, DWORD flags );
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen );
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen );
    
    ~RsaKey( );
};



inline
Key* Context::importKey( BYTE* pdata, DWORD dataLen, DWORD flags )
{
    return new RsaKey( this, pdata, dataLen, flags );
}



#endif
