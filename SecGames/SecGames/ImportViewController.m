//
//  ImportViewController.m
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import "ImportViewController.h"
#import "CryptoData.h"
#import "CapiOnEay.h"

@interface ImportViewController ()

@end


@implementation ImportViewController
@synthesize originalLabel = _originalLabel;
@synthesize decipheredLabel = _decipheredLabel;


- (IBAction)importPressed {
    NSString* original = [NSString stringWithUTF8String:rsaMsg.msg];
    self.originalLabel.text = original;
    HCRYPTPROV hprov;
    HCRYPTKEY hkey;
    
    CryptAcquireContext( &hprov );
    CryptImportKey(hprov, (BYTE*)&prvKeyExtract, sizeof(prvKeyExtract), 0, &hkey);
    
    DWORD dataLen = rsaMsg.size;
    BYTE buffer[400];
    memcpy( buffer, rsaMsg.cipher, dataLen );
    CryptDecrypt( hkey, true, 0, buffer, &dataLen );
    
    NSString* clear = [NSString stringWithUTF8String:(const char*)buffer];
    self.decipheredLabel.text = clear;


}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view.
}

- (void)viewDidUnload
{
    [self setOriginalLabel:nil];
    [self setDecipheredLabel:nil];
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

@end
