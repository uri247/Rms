//
//  EayP.cpp
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//


// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   Crypt.cpp
//
// Synopsis:    Contains implementation os the provider-independent classes.
//
// Author:      Uri London (v-uril@microsoft.com)
//


#include "Crypt.h"


// TODO: replace this with atomic increment (a-la Win32's InterlockedIncrement). Apple doesn't have
// this outside the kernel. For now, let's pretend these function are atomic.

int atomicTestAndInc( int* pval ) {
    int val = *pval;
    if( val > 0 ) {
        *pval = val+1;
    }
    return val;
}

int atomicDecrement( int* pval ) {
    int val = *pval;
    *pval = val-1;
    return val;
}



bool
CContext::addRef( )
{
    int count = atomicTestAndInc( &m_refCount );

    if( count == 0 ) {
        // You are trying to beat a dead horse. It was dereferenced to non existance.
        return false;
    }
    else {
        return true;
    }
}


void
CContext::release( )
{
    int count = atomicDecrement( &m_refCount );
    if( count == 0 ) {
        // call the virtual destructor
        delete this;
    }
}

