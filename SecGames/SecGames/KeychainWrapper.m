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
