//
//  SegViewController.m
//  SecGames
//
//  Created by Uri London on 8/8/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import "SegViewController.h"
#import "Security/Security.h"
#import "CryptoData.h"

@interface SegViewController ()

@end

@implementation SegViewController

@synthesize ttl;
@synthesize display;

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [self setDisplay:nil];
    [self setTtl:nil];
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

- (IBAction)genPressed:(UIButton*)sender {
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    
    NSMutableDictionary* privateAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* publicAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* pairAttr = [[NSMutableDictionary alloc] init];
    
    [pairAttr setObject:(id)CFBridgingRelease(kSecAttrKeyTypeRSA) forKey:(__bridge id)kSecAttrKeyType];
    [pairAttr setObject:[NSNumber numberWithUnsignedInt:1024] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [pairAttr setObject:privateAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [pairAttr setObject:publicAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    uint8_t privateIdentifier[] = "il.org.london.private";
    NSData* privateTag = [NSData dataWithBytes:privateIdentifier length:sizeof(privateIdentifier)];
    [privateAttr setObject:[NSNumber numberWithBool:NO] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    uint8_t publicIdentifier[] = "il.org.london.public";
    NSData* publicTag = [NSData dataWithBytes:publicIdentifier length:sizeof(publicIdentifier)];
    [publicAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicAttr setObject:publicTag forKey:(__bridge id)kSecAttrIsPermanent];
    
    SecKeyGeneratePair((__bridge CFDictionaryRef)pairAttr, &publicKey, &privateKey);
    
}

- (IBAction)rndPressed:(UIButton*)sender {
    uint8_t randomBuff[40];
    int i;
    SecRandomCopyBytes( kSecRandomDefault, 40, randomBuff );
    NSMutableString* str = [NSMutableString stringWithString:@""];
    for( i=0; i<40; ++i ) {
        [str appendFormat:@"%2x ", randomBuff[i]];
    }
    NSLog( @"Random 40 byts: %@", str );
    self.ttl.text = @"40 random bytes";
    self.display.text = str;
}

@end
