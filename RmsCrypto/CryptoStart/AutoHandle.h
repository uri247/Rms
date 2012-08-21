

class ProvTraits
{
public:
    static void close(HCRYPTPROV h) { CryptReleaseContext(h, 0); }
};

class KeyTraits
{
public:
    static void close(HCRYPTKEY h) { CryptDestroyKey(h); }
};


template< typename T, typename Tr >
class AutoHandle
{
public:
    T _handle;

    AutoHandle( T h )       { _handle = h; }
    AutoHandle( )           { _handle = NULL; }
    T* operator&( )         { return &_handle; }
    operator T( )           { return _handle; }
    ~AutoHandle( )          { Tr::close(_handle); }
};


typedef AutoHandle<HCRYPTPROV,ProvTraits> AutoCryptProv;
typedef AutoHandle<HCRYPTKEY,KeyTraits> AutoCryptKey;