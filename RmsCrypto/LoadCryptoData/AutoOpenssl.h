

class RsaDeleter
{
public:
    void operator()( RSA* rsa )     {
        RSA_free( rsa );
    }

};
