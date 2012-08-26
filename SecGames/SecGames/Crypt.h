// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   Crypt.h
//
// Synopsis:    Contains classes which implements the provider-independent implementation of the
//              IpcOSCryptXxxx classes. It is a library internal header
//
// Author:      Uri London (v-uril@microsoft.com)
//

#ifndef SecGames_Header_h
#define SecGames_Header_h

#include <mutex>
#include "windef.h"
#include "Handle.h"

class CContext;
class CKey;


//
//
// Base class of CContext. This is an abstract class that contains decleration of several virtual funcitons,
// actually defined in the template derived from this class
//

class CContext : public CHandle
{
private:
    std::mutex m_refLock;
    int m_refCount;

    
public:
    CContext( ) : CHandle(magic_Context) { m_refCount = 0; }
    virtual CKey* importKey( BYTE* pdata, DWORD dataLen, DWORD flags ) =0;
    virtual CKey* genKey( ) =0;
    bool addRef( );
    void release( );
    virtual ~CContext( )
    {
    }
};


template<class RSAKEY, class AESKEY, class RND, class HASH>
class ContextType : public CContext
{
public:
    typedef RSAKEY TyRsaKey;
    typedef AESKEY TyAesKey;
    typedef RND TyRandom;
    typedef HASH TyHash;
    
public:
    ContextType( ) { }
    CKey* importKey( BYTE* pdata, DWORD dataLen, DWORD flags ) {
        return new TyRsaKey( pdata, dataLen, flags );
    }
    CKey* genKey( ) {
        return NULL;
    }
    ~ContextType( )
    {
    }
};



class CKey : public CHandle
{
public:
    CKey( ) : CHandle(magic_Key) { }

public:
    virtual void Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen ) =0;
    virtual void Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen ) =0;
};



class CRandom : public CHandle
{
public:
    CRandom( ) : CHandle(magic_Random) { }
    
    
};



#endif
