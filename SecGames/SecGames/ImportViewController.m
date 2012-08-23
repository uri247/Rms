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
@synthesize decipheredLabel = _decipheredLabel;
@synthesize picker = _picker;
@synthesize messages = _messages;


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
    [self setDecipheredLabel:nil];
    [self setPicker:nil];
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
