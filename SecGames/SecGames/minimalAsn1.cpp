// Copyright (c) 2012 Microsoft corporation. All rights reserved.
//
// File Name:   minimalAsn1.h
//
// Synopsis:    The minimum ASN.1 that we need in order to import/export cryptographic keys to
//              Apple security key chain.
//
// Author:      Uri London (v-uril@microsoft.com)
//

#include <memory>
#include "minimalAsn1.h"
#include "CryptoData.h"

const BYTE ASN1MARK_INTEGER       = 0x02;
const BYTE ASN1MARK_SEQUANCE      = 0x30;


DWORD log256( DWORD x )
{
    // How many bytes do I need to represent x
    return ( x < 0x100 ) ? 1 :
    ( x < 0x10000 ) ? 2 :
    ( x < 0x1000000 ) ? 3 :
    4;
}

DWORD lenLen( DWORD len )
{
    return (len < 0x80) ? 1 : 1 + log256(len);
}

void encodeLength( BYTE*& dst, DWORD len )
{
    DWORD lenlen = lenLen(len);
    if( lenlen == 1 ) {
        *dst++ = (BYTE)len;
    }
    else {
        *dst++ = (BYTE)(0x80 + lenlen -1);
        if( lenlen >= 5 )
            *dst++ = (BYTE)( (len & 0xff000000) >> 24 );
        if( lenlen >= 4 )
            *dst++ = (BYTE)( (len & 0x00ff0000) >> 16 );
        if( lenlen >= 3 )
            *dst++ = (BYTE)( (len & 0x0000ff00) >> 8 );
        *dst++ = (BYTE)( len & 0x000000ff );
    }
}


DWORD encsizeLittleEndianInteger( BYTE* buffer, DWORD len )
{
    // if last byte is negative, we add extra zero
    DWORD extraZero = ( buffer[len-1] >= 0x80 ) ? 1 : 0;
    
    // 1st byte is the mark
    DWORD total = 1;
    
    // add length encoding
    total += lenLen( len + extraZero );
    
    // add length of data
    total += len + extraZero;
    
    return total;
}


void encodeLittleEndianInteger( BYTE*& dst, BYTE* src, DWORD len )
{
    DWORD extraZero = ( src[len-1] >= 0x80 ) ? 1 : 0;
    
    // mark
    *dst++ = ASN1MARK_INTEGER;
    
    // length
    encodeLength( dst, len + extraZero );
    
    // extra zero
    if( extraZero ) {
        *dst++ = 0x00;
    }
    
    // the integer, reversed to correct endianess
    for( DWORD i=0; i<len; ++i ) {
        *dst++ = src[len-i-1];
    }
}


void minimalAsn1PrivKey( BYTE* privKeyBlob, DWORD privKeyLength, BYTE** privKeyAsn1Blob, DWORD* privKeyAsn1Length )
{
    // decompose the private key blob
    BLOBHEADER* header = (BLOBHEADER*)privKeyBlob;
    RSAPUBKEY* rsapub = (RSAPUBKEY*)(header+1);
    
    BYTE version = 0;
    DWORD bytelen = rsapub->bitlen / 8;
    DWORD exponent = rsapub->pubexp;
    
    BYTE* modulus = (BYTE*)(rsapub+1);
    BYTE* prime1 = modulus + bytelen;
    BYTE* prime2 = prime1 + bytelen/2;
    BYTE* exp1 = prime2 + bytelen/2;
    BYTE* exp2 = exp1 + bytelen/2;
    BYTE* coefficient = exp2 + bytelen/2;
    BYTE* privExp = coefficient + bytelen/2;
    
    DWORD data_size =
    encsizeLittleEndianInteger( &version, 1 ) +
    encsizeLittleEndianInteger( modulus, bytelen ) +
    encsizeLittleEndianInteger( (BYTE*)&exponent, log256(exponent) ) +
    encsizeLittleEndianInteger( privExp, bytelen ) +
    encsizeLittleEndianInteger( prime1, bytelen/2 ) +
    encsizeLittleEndianInteger( prime2, bytelen/2 ) +
    encsizeLittleEndianInteger( exp1, bytelen/2 ) +
    encsizeLittleEndianInteger( exp2, bytelen/2 ) +
    encsizeLittleEndianInteger( coefficient, bytelen/2 );
    
    DWORD buffer_size = 1 + lenLen(data_size) + data_size;
    
    // allocate
    std::unique_ptr< BYTE[] > buff (new BYTE[buffer_size] );
    BYTE* dst = buff.get();
    
    // encode mark∫
    *dst++ = ASN1MARK_SEQUANCE;
    
    // encode length
    encodeLength( dst, data_size );
    
    // encode fields
    encodeLittleEndianInteger( dst, &version, 1 );
    encodeLittleEndianInteger( dst, modulus, bytelen );
    encodeLittleEndianInteger( dst, (BYTE*)&exponent, log256(exponent) );
    encodeLittleEndianInteger( dst, privExp, bytelen );
    encodeLittleEndianInteger( dst, prime1, bytelen/2 );
    encodeLittleEndianInteger( dst, prime2, bytelen/2 );
    encodeLittleEndianInteger( dst, exp1, bytelen/2 );
    encodeLittleEndianInteger( dst, exp2, bytelen/2 );
    encodeLittleEndianInteger( dst, coefficient, bytelen/2 );
    
    *privKeyAsn1Blob = buff.release();
    *privKeyAsn1Length = buffer_size;
    
}

