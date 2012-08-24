//
//  CryptOnKeychain.cpp
//  SecGames
//
//  Created by Uri London on 8/23/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//


#include <memory>
#include "minimalAsn1.h"
#include "KeychainWrapper.h"
#include "CryptOnKeychain.h"





kchn_RsaKey::kchn_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags )
{
    BYTE* asn1Buff;
    DWORD asn1BuffLength;
    minimalAsn1PrivKey( pdata, dataLen, &asn1Buff, &asn1BuffLength );
    importPrivateRsaKey( asn1Buff, asn1BuffLength, "david" );
}

void kchn_RsaKey::Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    unsigned long dataLen = *pdataLen;
    std::unique_ptr<BYTE[]> input( new BYTE[dataLen] );
    for( int i=0; i<dataLen; ++i ) {
        input[i] = pdata[ dataLen - i - 1 ];
    }
    
    std::unique_ptr<BYTE[]> output( new BYTE[dataLen] );

    decryptMsg( input.get(), output.get(), &dataLen, "david" );
    
    
    std::memcpy( pdata, output.get(), dataLen );

}

void kchn_RsaKey::Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen )
{

}
