//
//  minimalAsn1.h
//  SecGames
//
//  Created by Uri London on 8/24/12.
//  Copyright (c) 2012 Uri London. All rights reserved.
//

#ifndef __SecGames__minimalAsn1__
#define __SecGames__minimalAsn1__

#include <memory>
#include "windef.h"


void minimalAsn1PrivKey( BYTE* privKeyBlob, DWORD privKeyLength, BYTE** privKeyAsn1Blob, DWORD* privKeyAsn1Length );


#endif /* defined(__SecGames__minimalAsn1__) */
