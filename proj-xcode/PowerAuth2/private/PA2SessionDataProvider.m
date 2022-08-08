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

#import "PA2SessionDataProvider.h"
#import <PowerAuth2/PowerAuthLog.h>

@implementation PA2SessionDataProvider
{
    PowerAuthKeychain * _keychain;
    NSString * _statusKey;
}

- (nonnull instancetype) initWithKeychain:(nonnull PowerAuthKeychain*)keychain
                                statusKey:(nonnull NSString*)statusKey
{
    self = [super init];
    if (self) {
        _keychain = keychain;
        _statusKey = statusKey;
    }
    return self;
}

- (NSData*) sessionData
{
    OSStatus status = 0;
    NSData * result = [_keychain dataForKey:_statusKey status:&status];
    if (status != errSecSuccess && status != errSecItemNotFound) {
        PowerAuthLog(@"PA2SessionDataProvider: Failed to load session data. Error %@", @(status));
    }
    return result;
}

- (void) saveSessionData:(NSData *)sessionData
{
    if (sessionData) {
        if ([_keychain containsDataForKey:_statusKey]) {
            PowerAuthKeychainStoreItemResult r = [_keychain updateValue:sessionData forKey:_statusKey];
            if (r != PowerAuthKeychainStoreItemResult_Ok) {
                PowerAuthLog(@"PA2SessionDataProvider: Failed to update session data. Error %@", @(r));
            }
        } else {
            PowerAuthKeychainStoreItemResult r = [_keychain addValue:sessionData forKey:_statusKey];
            if (r != PowerAuthKeychainStoreItemResult_Ok) {
                PowerAuthLog(@"PA2SessionDataProvider: Failed to store session data. Error %@", @(r));
            }
        }
    } else {
        if (![_keychain deleteDataForKey:_statusKey]) {
            PowerAuthLog(@"PA2SessionDataProvider: Failed to remove session data.");
        }
    }
}

@end
