
#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int ALG_ID;


struct CSymmetricKeyExtract {
    BYTE bType;
    BYTE bVersion;
    WORD reserved;
    ALG_ID aiKeyAlg;
    DWORD size;
    BYTE blob[16];
};

struct CMsgData {
    const char* msg;
    BYTE cipher[400];
    int size;
};

struct CPublicKeyExtract {
    BYTE bType;
    BYTE bVersion;
    WORD reserved;
    ALG_ID aiKeyAlg;
    DWORD magic;
    DWORD bitlen;
    DWORD exponent;
    BYTE modulus[128];
};


struct CPrivateKeyExtract {
    BYTE bType;
    BYTE bVersion;
    WORD reserved;
    ALG_ID aiKeyAlg;
    DWORD magic;
    DWORD bitlen;
    DWORD exponent;
    BYTE modulus[128];
    BYTE prime1[64];
    BYTE prime2[64];
    BYTE exp1[64];
    BYTE exp2[64];
    BYTE coefficient[64];
    BYTE privExp[128];
};


extern BYTE symmetricKeyBlob[28];
extern struct CSymmetricKeyExtract symKeyExtract;
extern struct CMsgData symMsg1;
extern struct CMsgData symMsg2;
extern struct CMsgData symMsg3;
extern BYTE publicKeyBlob[148];
extern struct CPublicKeyExtract pubKeyExtract;
extern BYTE privateKeyBlob[596];
extern struct CPrivateKeyExtract prvKeyExtract;
extern struct CMsgData rsaMsg;

#ifdef  __cplusplus
}
#endif