//
//  KeychainWrapper.h
//  SecGames
//
//  Created by Uri London on 8/23/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//


#include "windef.h"

__EXTERN_C_ void importPrivateRsaKey( BYTE* privKeyAsn1, unsigned int length, const char* tag );
__EXTERN_C_ char* getBundleIdentifier( );
__EXTERN_C_ void decryptMsg( BYTE* cipher, BYTE* clear, unsigned long* plength, const char* tagSz );

