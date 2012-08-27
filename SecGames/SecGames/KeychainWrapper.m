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


void decryptMsg( BYTE* cipher, BYTE* clear, unsigned long* plength, const char* tagSz )
{
    OSStatus status;
    
    // create tag
    NSString* tagSt = [NSString stringWithUTF8String:tagSz];
    NSData* tag = [tagSt dataUsingEncoding:NSUTF8StringEncoding];

    SecKeyRef keyRef = nil;    
    NSMutableDictionary* prvKeyAttr = [[NSMutableDictionary alloc] init];
    [prvKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [prvKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [prvKeyAttr setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [prvKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    status = SecItemCopyMatching( (__bridge CFDictionaryRef)prvKeyAttr, (CFTypeRef*)&keyRef );
    NSLog( @"status %ld", status );

    status = SecKeyDecrypt( keyRef, kSecPaddingOAEP, cipher, *plength, clear, plength );
    NSLog( @"status %ld", status );
}



void randomCopyBytes( int length, BYTE* buffer )
{
    SecRandomCopyBytes( kSecRandomDefault, length, buffer );
}
