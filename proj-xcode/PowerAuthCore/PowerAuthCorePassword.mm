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

+ (instancetype) passwordWithString:(NSString *)string
{
    PowerAuthCorePassword * pass = [[PowerAuthCorePassword alloc] init];
    if (pass) {
        pass->_password.initAsImmutable(cc7::MakeRange(string.UTF8String));
    }
    return pass;
}

+ (instancetype) passwordWithData:(NSData *)data
{
    PowerAuthCorePassword * pass = [[PowerAuthCorePassword alloc] init];
    if (pass) {
        pass->_password.initAsImmutable(cc7::ByteRange(data.bytes, data.length));
    }
    return pass;
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

- (BOOL) validatePasswordComplexity:(BOOL (NS_NOESCAPE ^)(const UInt8* passphrase, NSUInteger length))validationBlock
{
    BOOL result = NO;
    const cc7::byte * plaintext_bytes = _password.passwordData().data();
    if (validationBlock && plaintext_bytes) {
        result = validationBlock(plaintext_bytes, _password.passwordData().size());
    }
    return result;
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

- (id) init
{
    self = [super init];
    if (self) {
        _password.initAsMutable();
    }
    return self;
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
