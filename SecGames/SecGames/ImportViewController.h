//
//  ImportViewController.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ImportViewController : UIViewController <UIPickerViewDelegate, UIPickerViewDataSource>

@property (weak, nonatomic) IBOutlet UILabel *originalLabel;
@property (weak, nonatomic) IBOutlet UILabel *recoveredWithOssl;

@property (weak, nonatomic) IBOutlet UILabel *recoveredWithKchn;
@property (weak, nonatomic) IBOutlet UIPickerView *picker;

@end
