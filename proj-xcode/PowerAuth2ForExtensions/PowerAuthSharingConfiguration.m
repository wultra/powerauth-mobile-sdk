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

#import <PowerAuth2ForExtensions/PowerAuthSharingConfiguration.h>
#import "PA2PrivateConstants.h"

#if PA2_HAS_CORE_MODULE
#import "PA2AppGroupContainer.h"
#endif

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

- (BOOL) validateConfiguration
{
    BOOL result = _appGroup.length > 0;
    result = result && (_appIdentifier.length > 0);
    result = result && ([_appIdentifier dataUsingEncoding:NSUTF8StringEncoding].length <= PADef_PowerAuthSharing_AppIdentifierMaxSize);
#if PA2_HAS_CORE_MODULE
    if (_sharedMemoryIdentifier) {
        result = result && [PA2AppGroupContainer validateShortSharedMemoryIdentifier:_sharedMemoryIdentifier];
    }
#endif
    return result;
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
