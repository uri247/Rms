//
//  ImportViewController.m
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import "ImportViewController.h"
#import "CryptoData.h"
#import "CryptInterface.h"

@interface ImportViewController ()
@property NSArray* messages;
@property NSArray* msgs;
@end


@implementation ImportViewController
{
    struct CMsgData* msgs[4];
}
@synthesize originalLabel = _originalLabel;
@synthesize recoveredWithOssl = _decipheredLabel;
@synthesize recoveredWithKchn = _recoveredViewKchn;
@synthesize picker = _picker;
@synthesize messages = _messages;


- (IBAction)importPressed {
    NSString* original = [NSString stringWithUTF8String:rsaMsg.msg];
    self.originalLabel.text = original;
    HCRYPTPROV hprovOssl, hprovKchn;
    HCRYPTKEY hkeyOssl, hkeyKchn;
    BYTE buffer[400];
    DWORD dataLen;
    
    //
    // Via OpenSSL
    //
    
    CryptAcquireContextOssl( &hprovOssl );
    CryptImportKey(hprovOssl, (BYTE*)&prvKeyExtract, sizeof(prvKeyExtract), 0, &hkeyOssl);
    dataLen = rsaMsg.size;
    memcpy( buffer, rsaMsg.cipher, dataLen );
    CryptDecrypt( hkeyOssl, true, 0, buffer, &dataLen );
    NSString* clear = [NSString stringWithUTF8String:(const char*)buffer];
    self.recoveredWithOssl.text = clear;
    
    
    //
    // Via KeyChain
    //
    
    CryptAcquireContextKchn( &hprovKchn );
    CryptImportKey(hprovKchn, (BYTE*)privateKeyBlob, sizeof(privateKeyBlob), 0, &hkeyKchn );
    dataLen = rsaMsg.size;
    memcpy( buffer, rsaMsg.cipher, dataLen );
    CryptDecrypt( hkeyKchn, true, 0, buffer, &dataLen );
    NSString* clear2 = [NSString stringWithUTF8String:(const char*)buffer];
    self.recoveredWithKchn.text = clear2;
}


- (void)setPicker:(UIPickerView *)picker
{
    _picker = picker;
    //self.picker.dataSource = self;
    //self.picker.delegate = self;
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
    self.messages = [NSArray arrayWithObjects:@"aes short", @"aes medium", @"aes long", @"rsa", nil];
    msgs[0] = &symMsg1;
    msgs[1] = &symMsg2;
    msgs[2] = &symMsg3;
    msgs[3] = &rsaMsg;
}


- (void)viewDidUnload
{
    [self setOriginalLabel:nil];
    [self setRecoveredWithOssl:nil];
    [self setPicker:nil];
    [self setRecoveredWithKchn:nil];
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

- (NSInteger)numberOfComponentsInPickerView:(UIPickerView*)pickerView
{
    return 1;
}


- (NSInteger)pickerView:(UIPickerView*)pickerView numberOfRowsInComponent:(NSInteger)component
{
    return [self.messages count];
}
    

- (NSString*)pickerView:(UIPickerView *)pickerView
            titleForRow:(NSInteger)row
           forComponent:(NSInteger)component
{
    return [self.messages objectAtIndex:row];
}

- (void)pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component
{
    struct CMsgData* msg = msgs[row];
    self.originalLabel.text = [NSString stringWithUTF8String:msg->msg];
}


@end
