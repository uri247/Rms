// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   minimalAsn1.h
//
// Synopsis:    The minimum ASN.1 that we need in order to import/export cryptographic keys to
//              Apple security key chain.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#ifndef __minimalAsn1_h_
#define __minimalAsn1_h_

#include "windef.h"


void minimalAsn1PrivKey( BYTE* privKeyBlob, DWORD privKeyLength, BYTE** privKeyAsn1Blob, DWORD* privKeyAsn1Length );
void minimalAsn1PubKey( BYTE* pubKeyBlob, DWORD pubKeyLength, BYTE** pubKeyAsn1Blob, DWORD* pubKeyAsn1Length );

#endif