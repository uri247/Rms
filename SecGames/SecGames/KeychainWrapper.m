// Copyright (c) 2012 Microsoft Corporation. All rights reserved.
//
// File:        KeyChainWrapper.c
//
// Synopsis:    This file wraps various Security Key Chain functions. Its interface is C style interface
//              so although interfal implementation uses Object-C method of Cocoa, it can be called
//              from C, C++ and Objective-C code
//              It is meant to be used mainly by the various classes of CryptOnKeychain.
//
// Author:      Uri London (v-uril)
//

#import <Security/SecRandom.h>
#import <CommonCrypto/CommonCryptor.h>
#import "KeychainWrapper.h"


void importPublicRsaKey( BYTE* pubKeyAsn1, unsigned int length, const char* tagSz )
{
    // create tag
    NSString* tagSt = [NSString stringWithUTF8String:tagSz];
    NSData* tag = [tagSt dataUsingEncoding:NSUTF8StringEncoding];

    // key attributes dictionary
    NSMutableDictionary* pubKeyAttr = [[NSMutableDictionary alloc] init];
    [pubKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [pubKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [pubKeyAttr setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];

    // First, delete the key if something left from before
    SecItemDelete((__bridge CFDictionaryRef)(pubKeyAttr));
    
    // more parameters to dictionary
    NSData* pubKeyData = [NSData dataWithBytes:pubKeyAsn1 length:length];
    [pubKeyAttr setObject:pubKeyData forKey:(__bridge id)kSecValueData];
    [pubKeyAttr setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [pubKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey;
    OSStatus osStatus = SecItemAdd( (__bridge CFDictionaryRef)pubKeyAttr, &persistKey );
    NSLog( @"status: %ld", osStatus );
    if( persistKey ) {
        CFRelease( persistKey );
    }
    
    // test:
    SecKeyRef keyRef = nil;
    [pubKeyAttr removeObjectForKey:(__bridge id)kSecValueData];
    [pubKeyAttr removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [pubKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [pubKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    SecItemCopyMatching( (__bridge CFDictionaryRef)pubKeyAttr, (CFTypeRef*)&keyRef );
}


void importPrivateRsaKey( BYTE* privKeyAsn1, unsigned int length, const char* tagSz )
{
    // create tag
    NSString* tagSt = [NSString stringWithUTF8String:tagSz];
    NSData* tag = [tagSt dataUsingEncoding:NSUTF8StringEncoding];
    
    // First, delete the key if something left from before
    NSMutableDictionary* prvKeyAttr = [[NSMutableDictionary alloc] init];
    [prvKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [prvKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [prvKeyAttr setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)(prvKeyAttr));

    // more parameters to dictionary
    NSData* prvKeyData = [NSData dataWithBytes:privKeyAsn1 length:length];
    [prvKeyAttr setObject:prvKeyData forKey:(__bridge id)kSecValueData];
    [prvKeyAttr setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [prvKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey;
    OSStatus osStatus = SecItemAdd( (__bridge CFDictionaryRef)prvKeyAttr, &persistKey );
    NSLog( @"status: %ld", osStatus );
    if( persistKey ) {
        CFRelease( persistKey );
    }

    SecKeyRef keyRef = nil;
    [prvKeyAttr removeObjectForKey:(__bridge id)kSecValueData];
    [prvKeyAttr removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [prvKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [prvKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    SecItemCopyMatching( (__bridge CFDictionaryRef)prvKeyAttr, (CFTypeRef*)&keyRef );
}


#define CSSM_ALGID_AES 


void genAesKey( const char* tagSz )
{
    // create the tag
    //NSData* tag = [NSData dataWithBytes:tagSz length:strlen(tagSz)+1];
    
}
    
/*
- (void)generateSymmetricKey {
	OSStatus sanityCheck = noErr;
	uint8_t * symmetricKey = NULL;
	
	// First delete current symmetric key.
	[self deleteSymmetricKey];
	
	// Container dictionary
	NSMutableDictionary *symmetricKeyAttr = [[NSMutableDictionary alloc] init];
	[symmetricKeyAttr setObject:(id)kSecClassKey forKey:(id)kSecClass];
	[symmetricKeyAttr setObject:symmetricTag forKey:(id)kSecAttrApplicationTag];
	[symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(id)kSecAttrKeyType];
	[symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)] forKey:(id)kSecAttrKeySizeInBits];
	[symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)]	forKey:(id)kSecAttrEffectiveKeySize];
	[symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanEncrypt];
	[symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanDecrypt];
	[symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanDerive];
	[symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanSign];
	[symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanVerify];
	[symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanWrap];
	[symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanUnwrap];
	
	// Allocate some buffer space. I don't trust calloc.
	symmetricKey = malloc( kChosenCipherKeySize * sizeof(uint8_t) );
	
	LOGGING_FACILITY( symmetricKey != NULL, @"Problem allocating buffer space for symmetric key generation." );
	
	memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);
	
	sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
	LOGGING_FACILITY1( sanityCheck == noErr, @"Problem generating the symmetric key, OSStatus == %d.", sanityCheck );
	
	self.symmetricKeyRef = [[NSData alloc] initWithBytes:(const void *)symmetricKey length:kChosenCipherKeySize];
	
	// Add the wrapped key data to the container dictionary.
	[symmetricKeyAttr setObject:self.symmetricKeyRef
                         forKey:(id)kSecValueData];
	
	// Add the symmetric key to the keychain.
	sanityCheck = SecItemAdd((CFDictionaryRef) symmetricKeyAttr, NULL);
	LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecDuplicateItem, @"Problem storing the symmetric key in the keychain, OSStatus == %d.", sanityCheck );
	
	if (symmetricKey) free(symmetricKey);
        [symmetricKeyAttr release];
}

*/

void importAesKey( BYTE* aesKey, unsigned int length, const char* tag )
{

}


SecKeyRef getKey( const char* tagSz )
{
    OSStatus status;

    // create tag
    NSData* tag = [[NSString stringWithUTF8String:tagSz] dataUsingEncoding:NSUTF8StringEncoding];

    SecKeyRef keyRef = nil;
    NSMutableDictionary* keyAttr = [[NSMutableDictionary alloc] init];
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    status = SecItemCopyMatching( (__bridge CFDictionaryRef)keyAttr, (CFTypeRef*)&keyRef );
    NSLog( @"status %ld", status );
    
    return keyRef;
}


void decryptMsg( BYTE* cipher, BYTE* clear, unsigned long* plength, const char* tagSz )
{
    OSStatus status;
    SecKeyRef keyRef = getKey( tagSz );
    status = SecKeyDecrypt( keyRef, kSecPaddingOAEP, cipher, *plength, clear, plength );
    NSLog( @"status %ld", status );
}


void encryptMsg( BYTE* clear, BYTE* cipher, unsigned long plength, unsigned long* buffLength, const char* tagSz )
{
    OSStatus status;
    SecKeyRef keyRef = getKey( tagSz );
    status = SecKeyEncrypt( keyRef, kSecPaddingOAEP, clear, plength, cipher, buffLength );
    NSLog( @"status %ld", status );
}


void randomCopyBytes( int length, BYTE* buffer )
{
    SecRandomCopyBytes( kSecRandomDefault, length, buffer );
}
