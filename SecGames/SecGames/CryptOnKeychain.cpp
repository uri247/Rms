// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   CryptOnKeychain
//
// Synopsis:    Implementation of RsaKey interface on top of Apple's iOS Security Key Chain framework.
//
// Author:      Uri London (v-uril@microsoft.com)
//


#include <memory>
#include <CommonCrypto/CommonCryptor.h>
#include "minimalAsn1.h"
#include "KeychainWrapper.h"
#include "CryptOnKeychain.h"





kchn_RsaKey::kchn_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags )
{
    BLOBHEADER* header = (BLOBHEADER*)pdata;
    BYTE* asn1Buff;
    DWORD asn1BuffLength;
    
    if( header->bType == 0x06 ) {
        minimalAsn1PubKey( pdata, dataLen, &asn1Buff, &asn1BuffLength );
        importPublicRsaKey( asn1Buff, asn1BuffLength, "pubkey" );
    }
    else if( header->bType == 0x07 ) {
        minimalAsn1PrivKey( pdata, dataLen, &asn1Buff, &asn1BuffLength );
        importPrivateRsaKey( asn1Buff, asn1BuffLength, "prvkey" );
    }
}

void kchn_RsaKey::Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    unsigned long dataLen = *pdataLen;
    std::unique_ptr<BYTE[]> input( new BYTE[dataLen] );
    for( int i=0; i<dataLen; ++i ) {
        input[i] = pdata[ dataLen - i - 1 ];
    }
    
    std::unique_ptr<BYTE[]> output( new BYTE[dataLen] );

    decryptMsg( input.get(), output.get(), &dataLen, "prvkey" );
    
    
    std::memcpy( pdata, output.get(), dataLen );

}

void kchn_RsaKey::Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen )
{
    DWORD outLength = bufLen;
    std::unique_ptr<BYTE[]> output( new BYTE[outLength] );
    encryptMsg( pdata, output.get(), *pdataLen, &outLength, "pubkey" );
    // assert( outLength < bufLen )
    for( int i=0; i<outLength; ++i )  {
        pdata[i] = output[ outLength -i - 1];
    }
    *pdataLen = outLength;
}


void CRandom::gen( DWORD len, BYTE* buffer )
{
    randomCopyBytes(len, buffer);
};



cc_AesKey::cc_AesKey( BYTE* pdata, DWORD dataLen, DWORD flags )
{
    BLOBHEADER* header = (BLOBHEADER*)pdata;
    DWORD* psize = (DWORD*)(header + 1);
    BYTE* pkey = (BYTE*)(psize + 1);
    DWORD size = *psize;
    
    // allocate buffer for the key and coppy
    m_key.reset( new BYTE[size] );
    memcpy( m_key.get(), pkey, size );
}

void cc_AesKey::Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    CCCryptorStatus status;
    std::unique_ptr<BYTE[]> dataOut;
    
    status = CCCrypt( kCCEncrypt, kCCAlgorithmAES128, 0, m_key.get(), m_keylen, NULL, pdata, *pdataLen, dataOut.get(), *pdataLen, pdataLen );
    memcpy( pdata, dataOut.get(), *pdataLen );
}

void cc_AesKey::Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD buflen )
{
    CCCryptorStatus status;
    std::unique_ptr<BYTE[]> dataOut;
    status = CCCrypt( kCCDecrypt, kCCAlgorithmAES128, 0, m_key.get(), m_keylen, NULL, pdata, *pdataLen, dataOut.get(), buflen, pdataLen );
    memcpy( pdata, dataOut.get(), *pdataLen );
}


