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



#define mk_magic(a,b,c,d)    (a<<24 | b<<16 | c<<8 | d)


//
// Base class for all handles returned by Win32.
//

class CHandle
{
private:
    DWORD m_magic;
    
public:
    CHandle( DWORD magic ) : m_magic(magic) { }

    template<class T> static T* h2c( HANDLE h ) {
        T* pointer = reinterpret_cast<T*>(h);
        DWORD m = *(reinterpret_cast<DWORD*>(pointer) + 1);
        if( m != T::class_magic() ) {
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
