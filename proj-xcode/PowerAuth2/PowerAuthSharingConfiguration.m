/*
 * Copyright 2022 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import "PowerAuthSharingConfiguration.h"
#import "PA2PrivateConstants.h"
#import "PA2AppGroupContainer.h"
#import "PA2PrivateMacros.h"

@implementation PowerAuthSharingConfiguration

- (instancetype) initWithAppGroup:(NSString*)appGroup
                    appIdentifier:(NSString*)appIdentifier
{
    self = [super init];
    if (self) {
        _appGroup = appGroup;
        _appIdentifier = appIdentifier;
    }
    return self;
}

- (instancetype) initWithAppGroup:(NSString*)appGroup
                    appIdentifier:(NSString*)appIdentifier
              keychainAccessGroup:(NSString*)keychainAccessGroup
{
    self = [super init];
    if (self) {
        _appGroup = appGroup;
        _appIdentifier = appIdentifier;
        _keychainAccessGroup = keychainAccessGroup;
    }
    return self;
}

- (BOOL) validateConfiguration:(NSError**)error
{
    if (!_appGroup.length) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthSharingConfiguration.appGroup is empty");
        return NO;
    }
    if (!_appIdentifier.length) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthSharingConfiguration.appIdentifier is empty");
        return NO;
    }
    if ([_appIdentifier dataUsingEncoding:NSUTF8StringEncoding].length > PADef_PowerAuthSharing_AppIdentifierMaxSize) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthSharingConfiguration.appIdentifier is too long");
        return NO;
    }
    if (_sharedMemoryIdentifier && ![PA2AppGroupContainer validateShortSharedMemoryIdentifier:_sharedMemoryIdentifier]) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthSharingConfiguration.sharedMemoryIdentifier is not valid");
        return NO;
    }
    return YES;
}

- (BOOL) validateConfiguration // PA2_DEPRECATED(2.0.0)
{
    return [self validateConfiguration:nil];
}

- (id) copyWithZone:(NSZone *)zone
{
    PowerAuthSharingConfiguration * c = [[self.class allocWithZone:zone] init];
    if (c) {
        c->_appGroup = _appGroup;
        c->_appIdentifier = _appIdentifier;
        c->_keychainAccessGroup = _keychainAccessGroup;
        c->_sharedMemoryIdentifier = _sharedMemoryIdentifier;
    }
    return c;
}

@end
