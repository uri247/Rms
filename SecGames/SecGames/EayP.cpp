//
//  EayP.cpp
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#include <memory>
#include <cstring>
#include <openssl/rsa.h>
#include "CapiOnEay.h"
#include "EayP.h"
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



RsaKey::RsaKey( Context* pctx, BYTE* pdata, DWORD dataLen, DWORD flags )
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

RsaKey::~RsaKey( )
{
    RSA_free( m_eayRsa );
    m_eayRsa = NULL;
}

void
RsaKey::Decrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen )
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
RsaKey::Encrypt( bool final, DWORD flags, BYTE* pdata, DWORD* pdataLen, DWORD bufLen )
{
    return;
}



