//
//  Header.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef SecGames_Header_h
#define SecGames_Header_h

#include "windef.h"


// big endian magic
DWORD const magic_Context = ('C'<<24 | 'N'<<16 | 'T'<<8 | 'X');
DWORD const magic_Key = ('K'<<24 | 'K'<<16 | 'E'<<8 | 'Y');


class CryptBase
{
private:
    DWORD m_magic;
    
protected:
    CryptBase( DWORD magic ) : m_magic(magic) { }
    
public:
    DWORD magic() { return m_magic; }
};


template<class KEY>
class ContextType : public CryptBase
{
public:
    ContextType( ) : CryptBase(magic_Context) { }
    KEY* importKey( BYTE* pdata, DWORD dataLen, DWORD flags ) {
        return new KEY( pdata, dataLen, flags );
    }
};



class Key : public CryptBase
{
public:
    Key( ) : CryptBase(magic_Key) { }

public:
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen ) =0;
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen ) =0;

};



#endif
