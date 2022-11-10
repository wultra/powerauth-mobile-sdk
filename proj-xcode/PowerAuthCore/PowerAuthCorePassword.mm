/*
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCorePassword.h>
#import "PowerAuthCorePrivateImpl.h"

#pragma mark -
#pragma mark Password -

@implementation PowerAuthCorePassword
{
@protected
    io::getlime::powerAuth::Password _password;
}

- (instancetype) initWithString:(NSString *)string
{
    self = [super init];
    if (self) {
        _password.initAsImmutable(cc7::MakeRange(string.UTF8String));
    }
    return self;
}

- (instancetype) initWithData:(NSData *)data
{
    self = [super init];
    if (self) {
        _password.initAsImmutable(cc7::ByteRange(data.bytes, data.length));
    }
    return self;
}

- (instancetype) initWithCopy:(nonnull PowerAuthCorePassword*)other
{
    self = [super init];
    if (self) {
        _password.initAsImmutable(other->_password.passwordData());
    }
    return self;
}

- (instancetype) initMutable
{
    self = [super init];
    if (self) {
        _password.initAsMutable();
    }
    return self;
}

+ (instancetype) passwordWithString:(NSString *)string
{
    return [[PowerAuthCorePassword alloc] initWithString:string];
}

+ (instancetype) passwordWithData:(NSData *)data
{
    return [[PowerAuthCorePassword alloc] initWithData:data];
}

- (NSUInteger) length
{
    return _password.length();
}

- (BOOL) isEqualToPassword:(PowerAuthCorePassword *)password
{
    if (self == password) {
        return YES;
    } else if (!password) {
        return NO;
    }
    return _password.isEqualToPassword(password->_password);
}

- (BOOL) isEqual:(id)object
{
    if (object == self) {
        return YES;
    }
    if ([object isKindOfClass:[PowerAuthCorePassword class]]) {
        return [self isEqualToPassword:object];
    }
    return NO;
}

- (NSInteger) validatePasswordComplexity:(NSInteger (NS_NOESCAPE ^)(const char* passphrase, NSInteger length))validationBlock
{
    auto plaintext = _password.passwordData();
    auto size = plaintext.size();
    // Append null terminator in case that consumer would like to use the pointer
    // in functions that accept c-style strings. The validation block still gets
    // the correct size.
    plaintext.append(0);
    return validationBlock((const char*)plaintext.data(), size);
}

- (void) secureClear
{
    _password.secureClear();
}

- (PowerAuthCorePassword*) copyToImmutable
{
    return [[PowerAuthCorePassword alloc] initWithCopy:self];
}

@end


#pragma mark -
#pragma mark Password (Private) -

@implementation PowerAuthCorePassword (Private)

- (io::getlime::powerAuth::Password &) passObjRef
{
    return _password;
}

@end



#pragma mark -
#pragma mark Mutable password -

@implementation PowerAuthCoreMutablePassword

- (instancetype) init
{
    return [super initMutable];
}

+ (instancetype) mutablePassword
{
    return [[PowerAuthCoreMutablePassword alloc] init];
}

- (void) clear
{
    _password.clear();
}

- (BOOL) addCharacter:(UInt32)character
{
    return _password.addCharacter(character);
}

- (BOOL) insertCharacter:(UInt32)character atIndex:(NSUInteger)index
{
    return _password.insertCharacter(character, index);
}

- (BOOL) removeLastCharacter
{
    return _password.removeLastCharacter();
}

- (BOOL) removeCharacterAtIndex:(NSUInteger)index
{
    return _password.removeCharacter(index);
}

@end
