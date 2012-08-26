// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   Handle.h
//
// Synopsis:    CHandle is the base class of all handles returned by Win32 (HANDLE, HKEY, HCRYPTPROV,
//              HFILE, etc.).
//
// Impl:        In current implementation, the handles returned to the caller are simply a pointer
//              to the structure holding the object state. We are putting a 'magic' DWORD at the
//              beginning of each structure, both to verify the integrity of the object, and also
//              to identify an area of memory
//
// Author:      Uri London (v-uril@microsoft.com)
//


#ifndef __HANDLE_H_
#define __HANDLE_H_

#include "windef.h"


DWORD const magic_Context = ('C'<<24 | 'N'<<16 | 'T'<<8 | 'X');
DWORD const magic_Key = ('K'<<24 | 'K'<<16 | 'E'<<8 | 'Y');
DWORD const magic_Random = ('P'<<24 | 'R'<<16 | 'N'<<8 | 'G');


//
// Base class for all handles returned by Win32.
//

class CHandle
{
private:
    DWORD m_magic;
    
public:
    CHandle( DWORD magic ) : m_magic(magic) { }
    DWORD magic() { return m_magic; }
    
    // Convert handle to pointer. Currently, handles are simply pointers to structure. If we choose in the future
    // to go to Dictionary style translation a-la Win32, this is the only place to change.
    template<class T> static T* h2c( HANDLE h ) {
        return (T*)h;
    }
    
    // Convert a structure into a handle. For now we just cast
    template<class T> static HANDLE c2h( T* object ) {
        return (HANDLE)object;
    }
};


#endif
