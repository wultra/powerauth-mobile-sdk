/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PowerAuthPassword.h"
#import <PowerAuthCore/PowerAuthCorePass.h>

@implementation PowerAuthPassword
{
@protected
    PowerAuthCorePass * _password;
}

- (PowerAuthCorePass*) corePassword
{
    return _password;
}

- (nonnull instancetype) initWithCorePassword:(nonnull PowerAuthCorePass*)password
{
    self = [super init];
    if (self) {
        _password = password;
    }
    return self;
}

- (nonnull instancetype) initWithString:(nonnull NSString*)string
{
    self = [super init];
    if (self) {
        _password = [[PowerAuthCorePass alloc] initWithString:string];
    }
    return self;
}

- (nonnull instancetype) initWithData:(nonnull NSData*)data
{
    self = [super init];
    if (self) {
        _password = [[PowerAuthCorePass alloc] initWithData:data];
    }
    return self;
}

+ (nonnull instancetype) passwordWithString:(nonnull NSString*)string
{
    return [[PowerAuthPassword alloc] initWithString:string];
}

+ (nonnull instancetype) passwordWithData:(nonnull NSData*)data
{
    return [[PowerAuthPassword alloc] initWithData:data];
}

- (NSUInteger) length
{
    return [_password length];
}

- (BOOL) isEqualToPassword:(nullable PowerAuthPassword*)password
{
    if (self == password) {
        return YES;
    }
    return [_password isEqualToPassword:password.corePassword];
}

- (BOOL) isEqual:(id)object
{
    if (object == self) {
        return YES;
    }
    if ([object isKindOfClass:[PowerAuthPassword class]]) {
        return [self isEqualToPassword:object];
    }
    return NO;
}

- (NSInteger) validatePasswordComplexity:(NSInteger (NS_NOESCAPE ^_Nonnull)(const char * _Nonnull  passphrase, NSInteger length))validationBlock
{
    return [_password validatePasswordComplexity:validationBlock];
}

- (void) secureClear
{
    [_password secureClear];
}

- (nonnull PowerAuthPassword*) copyToImmutable
{
    return [[PowerAuthPassword alloc] initWithCorePassword:[_password copyToImmutable]];
}

@end


@implementation PowerAuthMutablePassword

- (nonnull instancetype) init
{
    self = [super initWithCorePassword:[PowerAuthCoreMutablePass mutablePassword]];
    return self;
}

+ (nonnull instancetype) mutablePassword
{
    return [[PowerAuthMutablePassword alloc] init];
}

- (void) clear
{
    [(PowerAuthCoreMutablePass*)_password clear];
}

- (BOOL) addCharacter:(UInt32)character
{
    return [(PowerAuthCoreMutablePass*)_password addCharacter:character];
}

- (BOOL) insertCharacter:(UInt32)character atIndex:(NSUInteger)index
{
    return [(PowerAuthCoreMutablePass*)_password insertCharacter:character atIndex:index];
}

- (BOOL) removeLastCharacter
{
    return [(PowerAuthCoreMutablePass*)_password removeLastCharacter];
}

- (BOOL) removeCharacterAtIndex:(NSUInteger)index
{
    return [(PowerAuthCoreMutablePass*)_password removeCharacterAtIndex:index];
}

@end
