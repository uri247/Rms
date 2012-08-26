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


const WORD magic_Handle = ('H'<<8 | 'N');
#define mk_magic(a,b) (magic_Handle<<16 | a<<8 | b)
DWORD const magic_Context = mk_magic('T', 'X');
DWORD const magic_Key     = mk_magic('K', 'E');
DWORD const magic_Random  = mk_magic('R', 'N');


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
    // Our integrity check isn't a boolet proof to say the least, but we do want to verify the second DWORD (immediately
    // after the vptr is the magic
    template<class T> static T* h2c( HANDLE h ) {
        T* pointer = reinterpret_cast<T*>(h);
        DWORD magic = *(reinterpret_cast<DWORD*>(pointer) + 1);
        WORD mg = magic>>16;
        if( mg != magic_Handle ) {
            // Something went really wrong. We have an invalid handle
            throw (int)ERROR_INVALID_HANDLE;
        }
        return pointer;
    }
    
    // Convert a structure into a handle. For now we just cast. If/When we want to have a dictionary, there is where we
    // put the object in the dictionary.
    template<class T> static HANDLE c2h( T* object ) {
        return reinterpret_cast<HANDLE>(object);
    }
};


#endif
