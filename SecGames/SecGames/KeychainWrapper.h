// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   KeychainWrapper.h
//
// Synopsis:    A wrapper arround some Cocoa security key chain API, callable from C++ code
//
// Author:      Uri London (v-uril@microsoft.com)
//



#include "windef.h"

__EXTERN_C_ void importPrivateRsaKey( BYTE* privKeyAsn1, unsigned int length, const char* tag );
__EXTERN_C_ char* getBundleIdentifier( );
__EXTERN_C_ void decryptMsg( BYTE* cipher, BYTE* clear, unsigned long* plength, const char* tagSz );

