// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   CryptOnOpenSSL.cpp
//
// Synopsis:    Implementation of RsaKey interface using the OpenSSL library.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#include <memory>
#include "CryptOnOpenSSL.h"
#include "CryptoData.h"

int lend_tobn( BIGNUM *bn, unsigned char *bin, int binlen )
{
	int i;
    std::unique_ptr<BYTE[]> buffer( new BYTE[binlen] );
    
    for( i=0; i<binlen; ++i ) {
        buffer[i] = bin[binlen - i - 1];
    }
    
    int ret = BN_bin2bn( buffer.get(), binlen, bn ) ? 1 : 0;
    
    return ret;
}



ossl_RsaKey::ossl_RsaKey( BYTE* pdata, DWORD dataLen, DWORD flags )
{
    RSA* rsa;
    
    CPrivateKeyExtract* prv = (CPrivateKeyExtract*)pdata;
    
    rsa = RSA_new( );
    rsa->n = BN_new( );
    rsa->e = BN_new( );
    rsa->d = BN_new( );
    rsa->p = BN_new( );
    rsa->q = BN_new( );
    rsa->dmp1 = BN_new( );
    rsa->dmq1 = BN_new( );
    rsa->iqmp = BN_new( );
    
    BN_set_word( rsa->e, prv->exponent );
    lend_tobn( rsa->n, prv->modulus, prvKeyExtract.bitlen/8 );
    lend_tobn( rsa->p, prv->prime1, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->q, prv->prime2, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->d, prv->privExp, prvKeyExtract.bitlen/8 );
    lend_tobn( rsa->dmp1, prv->exp1, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->dmq1, prv->exp2, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->iqmp, prv->coefficient, prvKeyExtract.bitlen/16 );
    
    this->m_eayRsa = rsa;
}

ossl_RsaKey::~ossl_RsaKey( )
{
    RSA_free( m_eayRsa );
    m_eayRsa = NULL;
}

void
ossl_RsaKey::Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
{
    DWORD dataLen = *pdataLen;
    std::unique_ptr<BYTE[]> input( new BYTE[dataLen] );
    //BYTE input[128];
    for( int i=0; i<dataLen; ++i ) {
        input[i] = pdata[ dataLen - i - 1 ];
    }
    
    std::unique_ptr<BYTE[]> output( new BYTE[dataLen] );
    //BYTE output[128];
    RSA_private_decrypt( dataLen, input.get(), output.get(), m_eayRsa, RSA_PKCS1_OAEP_PADDING );
    
    std::memcpy( pdata, output.get(), dataLen );
    
}


void
ossl_RsaKey::Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen )
{
    return;
}

