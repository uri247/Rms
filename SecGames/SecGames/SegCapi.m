//
//  SegCapi.m
//  SecGames
//
//  Created by Uri London on 8/20/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#import "SegCapi.h"

@implementation SegCapi

@end



@implementation SegContext

+ (SegContext*)AcquireContext
{
    return [[self alloc] init];
}

- (SegKey*)ImportKey:(NSData*)data
{
    return [SegKey keyWithData:data];
}
@end



@implementation SegKey

+ (SegKey*)keyWithData:(NSData *)data
{
    return [[SegKey alloc] initWithData:data];
}

- (id)initWithData:(NSData *)data
{
    return nil;
}

@end