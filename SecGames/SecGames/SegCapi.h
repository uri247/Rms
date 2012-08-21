//
//  SegCapi.h
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SegCapi;
@class SegContext;
@class SegKey;



@interface SegCapi : NSObject
@end


@interface SegContext : NSObject
+ (SegContext*)AcquireContext;
- (SegKey*)ImportKey:(NSData*)data;
@end



@interface SegKey : NSObject
+ (SegKey*)keyWithData:(NSData*)data;
- (id)initWithData:(NSData*)data;
@end
