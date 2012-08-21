
#include "stdafx.h"
#include "../CryptoStart/AutoHandle.h"
#include "../CryptoStart/AutoResult.h"
#include "AutoOpenssl.h"
#include "CryptoData.h"

void theCapiWay( );
void theOpenSslWay( );


int wmain( int argc, wchar_t* argv[] )
{
    theCapiWay( );
    theOpenSslWay( );
    return 0;
}



void theCapiWay( )
{
    AutoCryptProv hprov;
    AutoCryptKey hkeyAes;
    AutoCryptKey hkeyRsa;
    BoolResult br;
    std::unique_ptr<BYTE[]> buffer( new BYTE[2000] );
    DWORD length;

    br << CryptAcquireContext( &hprov, NULL, NULL, PROV_RSA_AES, CRYPT_DELETEKEYSET );
    br << CryptAcquireContext( &hprov, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET );

    // symmetric message
    br << CryptImportKey( hprov, (BYTE*)&symKeyExtract, sizeof(symmetricKeyBlob), NULL, CRYPT_OAEP, &hkeyAes );
    memcpy( buffer.get(), symMsg3.cipher, sizeof(symMsg3.cipher) );
    length = symMsg3.size;
    br << CryptDecrypt( hkeyAes, NULL, TRUE, CRYPT_OAEP, buffer.get(), &length );
    std::cout << "capi aes message: " << (char*)buffer.get() << std::endl;

    // asymmetric message
    br << CryptImportKey( hprov, privateKeyBlob, sizeof(prvKeyExtract), NULL, 0, &hkeyRsa );
    memcpy( buffer.get(), rsaMsg.cipher, sizeof(rsaMsg.cipher) );
    length = rsaMsg.size;
    br << CryptDecrypt( hkeyRsa, NULL, TRUE, CRYPT_OAEP, buffer.get(), &length );
    std::cout << "capi rsa message: " << (char*)buffer.get() << std::endl << std::endl;

}


void opensslAes( )
{
    EVP_CIPHER_CTX ctx;
    std::unique_ptr<BYTE[]> output( new BYTE[symMsg3.size] );
    int outlen1;
    int outlen2;

    EVP_DecryptInit( &ctx, EVP_aes_128_cbc(), symKeyExtract.blob, NULL );
    EVP_DecryptUpdate( &ctx, output.get(), &outlen1, symMsg3.cipher, symMsg3.size );
    EVP_DecryptFinal( &ctx, output.get()+outlen1,&outlen2 );

    EVP_CIPHER_CTX_cleanup( &ctx );

    std::cout << "openssl aes message: " << (char*)output.get() << std::endl;
}


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

void saveBuffToFile( BUF_MEM* buff, const char* fname )
{
    std::ofstream os( fname, std::ofstream::binary );
    os.write( buff->data, buff->length );
    os.close( );
}



void opensslRsa( )
{
    std::unique_ptr< RSA, RsaDeleter > rsa( RSA_new() );
    int result;

    rsa->n = BN_new( );
    rsa->e = BN_new( );
    rsa->d = BN_new( );
    rsa->p = BN_new( );
    rsa->q = BN_new( );
    rsa->dmp1 = BN_new( );
    rsa->dmq1 = BN_new( );
    rsa->iqmp = BN_new( );

    BN_set_word( rsa->e, prvKeyExtract.exponent );
    lend_tobn( rsa->n, prvKeyExtract.modulus, prvKeyExtract.bitlen/8 );
    lend_tobn( rsa->p, prvKeyExtract.prime1, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->q, prvKeyExtract.prime2, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->d, prvKeyExtract.privExp, prvKeyExtract.bitlen/8 );
    lend_tobn( rsa->dmp1, prvKeyExtract.exp1, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->dmq1, prvKeyExtract.exp2, prvKeyExtract.bitlen/16 );
    lend_tobn( rsa->iqmp, prvKeyExtract.coefficient, prvKeyExtract.bitlen/16 );


    // copy input reverse
    std::unique_ptr<BYTE[]> input( new BYTE[rsaMsg.size] );
    std::unique_ptr<BYTE[]> output( new BYTE[rsaMsg.size] );
    for( int i=0; i<rsaMsg.size; ++i ) {
        input[i] = rsaMsg.cipher[rsaMsg.size-i-1];
    }

    RSA_private_decrypt( rsaMsg.size, input.get(), output.get(), rsa.get(), RSA_PKCS1_OAEP_PADDING );
    
    std::cout << "openssl rsa message: " << (char*)output.get() << std::endl;


    // Do some savings
    BIO* biomem;
    BUF_MEM* buff;

    biomem = BIO_new( BIO_s_mem() );
    result = PEM_write_bio_RSAPrivateKey( biomem, rsa.get(), NULL, NULL, 0, NULL, NULL );
    BIO_get_mem_ptr(biomem, &buff);
    saveBuffToFile( buff, "priv.pem" );
    BIO_free(biomem);
        
    biomem = BIO_new( BIO_s_mem() );
    result = PEM_write_bio_RSAPublicKey( biomem, rsa.get() );
    BIO_get_mem_ptr(biomem, &buff);
    saveBuffToFile( buff, "pub.pem" );
    BIO_free(biomem);

}


void theOpenSslWay( )
{
    opensslAes(  );
    opensslRsa(  );
}

