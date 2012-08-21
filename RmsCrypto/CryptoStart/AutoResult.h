

class Win32Exception : public std::exception
{
public:
    DWORD _lastError;

public:
    Win32Exception( DWORD lastError ) :_lastError(lastError) { }
};



class BoolResult
{
private:
    const char* _file;
    int _line;

public:
    BoolResult( const char* file, int line ) : _file(file), _line(line) { }
    BoolResult( ) { }

    void operator<<( BOOL result ) {
        if( !result ) {
            DWORD gle = GetLastError();
            throw Win32Exception(gle);
        }
    }

    BOOL operator=( BOOL result ) {
        // do nothing
        return result;
    }
};



