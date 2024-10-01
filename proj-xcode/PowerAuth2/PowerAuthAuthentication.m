/**
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

#import <PowerAuth2/PowerAuthAuthentication.h>
#import <PowerAuth2/PowerAuthKeychainAuthentication.h>
#import <PowerAuth2/PowerAuthLog.h>
#import "PowerAuthAuthentication+Private.h"

@import PowerAuthCore;

@implementation PowerAuthAuthentication
{
    NSInteger _objectUsage;
}

#define AUTH_FOR_PERSIST        1
#define AUTH_FOR_SIGN           2

- (id) initWithObjectUsage:(NSInteger)objectUsage
                  password:(PowerAuthCorePassword*)password
                  biometry:(BOOL)biometry
            biometryPrompt:(NSString*)biometryPrompt
           biometryContext:(id)biometryContext
       customPossessionKey:(NSData*)customPossessionKey
         customBiometryKey:(NSData*)customBiometryKey
{
    self = [super init];
    if (self) {
        _objectUsage = objectUsage;
        _usePossession = YES;
        _password = password;
        _useBiometry = biometry;
        _biometryPrompt = biometryPrompt;
        _biometryContext = biometryContext;
        _overridenPossessionKey = customPossessionKey;
        _overridenBiometryKey = customBiometryKey;
    }
    return self;
}

- (id) copyWithZone:(NSZone *)zone
{
    PowerAuthAuthentication * copy = [[[self class] allocWithZone:zone] init];
    if (copy) {
        copy->_objectUsage = _objectUsage;
        copy->_usePossession = _usePossession;
        copy->_useBiometry = _useBiometry;
        copy->_password = _password;
        copy->_biometryPrompt = _biometryPrompt;
        copy->_overridenPossessionKey = _overridenPossessionKey;
        copy->_overridenBiometryKey = _overridenBiometryKey;
#if PA2_HAS_LACONTEXT == 1
        copy->_biometryContext = _biometryContext;
#endif
    }
    return copy;
}

- (PowerAuthKeychainAuthentication *) keychainAuthentication
{
#if PA2_HAS_LACONTEXT == 1
    if (_biometryContext) {
        return [[PowerAuthKeychainAuthentication alloc] initWithContext:_biometryContext];
    }
#endif // PA2_HAS_LACONTEXT
    if (_biometryPrompt) {
        return [[PowerAuthKeychainAuthentication alloc] initWithPrompt:_biometryPrompt];
    }
    return nil;
}

#if DEBUG
- (NSString*) description
{
    NSString * usage_str;
    if (_objectUsage == AUTH_FOR_SIGN) {
        usage_str = @"for sign";
    } else {
        usage_str = @"for persist";
    }
    NSMutableArray * factors = [NSMutableArray arrayWithCapacity:3];
    if (_usePossession) {
        [factors addObject:@"possession"];
    }
    if (_password) {
        [factors addObject:@"knowledge"];
    }
    if (_useBiometry) {
        [factors addObject:@"biometry"];
    }
    NSString * factors_str = [factors componentsJoinedByString:@"_"];
    NSMutableArray * info = [NSMutableArray array];
    if (_biometryPrompt) {
        [info addObject:@"+prompt"];
    }
#if PA2_HAS_LACONTEXT == 1
    if (_biometryContext) {
        [info addObject:@"+context"];
    }
#endif
    if (_overridenBiometryKey) {
        [info addObject:@"+extBK"];
    }
    if (_overridenPossessionKey) {
        [info addObject:@"+extPK"];
    }
    NSString * info_str = info.count == 0 ? @"" : [@", " stringByAppendingString:[info componentsJoinedByString:@" "]];
    return [NSString stringWithFormat:@"<PowerAuthAuthentication %@: %@%@>", usage_str, factors_str, info_str];
}
#endif

@end


@implementation PowerAuthAuthentication (EasyAccessors)

// MARK: - Persist, Possession + Knowledge

+ (PowerAuthAuthentication*) persistWithPassword:(NSString*)password
{
    return [self persistWithCorePassword:[PowerAuthCorePassword passwordWithString:password]];
}

+ (PowerAuthAuthentication*) persistWithPassword:(NSString*)password
                             customPossessionKey:(NSData*)customPossessionKey
{
    return [self persistWithCorePassword:[PowerAuthCorePassword passwordWithString:password]
                     customPossessionKey:customPossessionKey];
}

// MARK: Persist, Possession + Knowledge + Biometry

+ (PowerAuthAuthentication*) persistWithPasswordAndBiometry:(NSString*)password
{
    return [self persistWithCorePasswordAndBiometry:[PowerAuthCorePassword passwordWithString:password]];
}

+ (PowerAuthAuthentication*) persistWithPasswordAndBiometry:(NSString*)password
                                          customBiometryKey:(NSData*)customBiometryKey
                                        customPossessionKey:(NSData*)customPossessionKey
{
    return [self persistWithCorePasswordAndBiometry:[PowerAuthCorePassword passwordWithString:password]
                                  customBiometryKey:customBiometryKey
                                customPossessionKey:customPossessionKey];
}

// MARK: Commit, Possession + Knowledge + Biometry

+ (PowerAuthAuthentication*) commitWithPasswordAndBiometry:(NSString*)password
{
    return [self persistWithPasswordAndBiometry:password];
}

+ (PowerAuthAuthentication*) commitWithPasswordAndBiometry:(NSString*)password
                                         customBiometryKey:(NSData*)customBiometryKey
                                       customPossessionKey:(NSData*)customPossessionKey
{
    return [self persistWithPasswordAndBiometry:password
                              customBiometryKey:customBiometryKey
                            customPossessionKey:customPossessionKey];
}



// MARK: - Signing, Possession only

+ (PowerAuthAuthentication *) possession
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithCustomPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:nil];
}

// MARK: Signing, Possession + Biometry

+ (PowerAuthAuthentication *) possessionWithBiometry
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:biometryPrompt
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
                                       customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:biometryPrompt
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryWithCustomBiometryKey:(NSData*)customBiometryKey
                                                      customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:customBiometryKey];
}

#if PA2_HAS_LACONTEXT == 1
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext *)context
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:context
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext*)context
                                        customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:nil
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:context
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:nil];
}
#endif // PA2_HAS_LACONTEXT

// MARK: Signing, Possession + Knowledge

+ (PowerAuthAuthentication *) possessionWithPassword:(NSString *)password
{
    return [self possessionWithCorePassword:[PowerAuthCorePassword passwordWithString:password]];
}

+ (PowerAuthAuthentication *) possessionWithPassword:(NSString*)password
                                 customPossessionKey:(NSData*)customPossessionKey
{
    return [self possessionWithCorePassword:[PowerAuthCorePassword passwordWithString:password]
                        customPossessionKey:customPossessionKey];
}

@end

#pragma mark - PowerAuthCorePassword

@implementation PowerAuthAuthentication (CorePassword)

+ (PowerAuthAuthentication*) persistWithCorePassword:(PowerAuthCorePassword*)password
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_PERSIST
                                                       password:password
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication*) persistWithCorePassword:(PowerAuthCorePassword*)password
                                 customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_PERSIST
                                                       password:password
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication*) persistWithCorePasswordAndBiometry:(PowerAuthCorePassword*)password
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_PERSIST
                                                       password:password
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication*) persistWithCorePasswordAndBiometry:(PowerAuthCorePassword*)password
                                              customBiometryKey:(NSData*)customBiometryKey
                                            customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_PERSIST
                                                       password:password
                                                       biometry:YES
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:customBiometryKey];
}

+ (PowerAuthAuthentication *) possessionWithCorePassword:(PowerAuthCorePassword*)password
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:password
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:nil
                                              customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithCorePassword:(PowerAuthCorePassword*)password
                                     customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithObjectUsage:AUTH_FOR_SIGN
                                                       password:password
                                                       biometry:NO
                                                 biometryPrompt:nil
                                                biometryContext:nil
                                            customPossessionKey:customPossessionKey
                                              customBiometryKey:nil];
}

@end


#pragma mark - Private

@implementation PowerAuthAuthentication (Private)

- (NSInteger) signatureFactorMask
{
    NSUInteger result = 0;
    if (_usePossession) result |= 1;
    if (_password)      result |= 2;
    if (_useBiometry)   result |= 4;
    return result;
}

- (BOOL) validateUsage:(BOOL)forPersist
{
    if (forPersist != (_objectUsage == AUTH_FOR_PERSIST)) {
        if (forPersist) {
            PowerAuthLog(@"WARNING: Using PowerAuthAuthentication object for a different purpose. The object for activation persist is expected.");
        } else {
            PowerAuthLog(@"WARNING: Using PowerAuthAuthentication object for a different purpose. The object for signature calculation is expected.");
        }
        return NO;
    }
    return YES;
}

@end
