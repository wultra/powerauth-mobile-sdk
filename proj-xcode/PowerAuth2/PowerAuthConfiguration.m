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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2/PowerAuthConfiguration.h>
#import <PowerAuth2/PowerAuthLog.h>
#import <PowerAuthCore/PowerAuthCore.h>
#import "PA2PrivateMacros.h"

@implementation PowerAuthConfiguration

#define MIN_OFFLINE_AUTH_CODE_COMPONENT_LEN 4
#define MAX_OFFLINE_AUTH_CODE_COMPONENT_LEN 8

- (id) init
{
    self = [super init];
    if (self) {
        _algorithm = PowerAuthAlgorithm_DEFAULT;
        _offlineAuthenticationCodeComponentLength = MAX_OFFLINE_AUTH_CODE_COMPONENT_LEN;
    }
    return self;
}

- (id) initWithInstanceId:(NSString *)instanceId baseEndpointUrl:(NSString *)baseEndpointUrl configuration:(NSString *)configuration algorithm:(PowerAuthAlgorithm)algorithm
{
    self = [super init];
    if (self) {
        _instanceId = instanceId;
        _baseEndpointUrl = baseEndpointUrl;
        _configuration = configuration;
        _algorithm = algorithm;
        _offlineAuthenticationCodeComponentLength = MAX_OFFLINE_AUTH_CODE_COMPONENT_LEN;
    }
    return self;
}

- (id) initWithInstanceId:(NSString *)instanceId baseEndpointUrl:(NSString *)baseEndpointUrl configuration:(NSString *)configuration
{
    return [self initWithInstanceId:instanceId baseEndpointUrl:baseEndpointUrl configuration:configuration algorithm:PowerAuthAlgorithm_DEFAULT];
}

- (BOOL) validateConfiguration // PA2_DEPRECATED(2.0.0)
{
    return [self validateConfiguration:nil];
}

- (BOOL) validateConfiguration:(NSError**)error
{
    if (!_instanceId.length) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthConfiguration.instanceId property is empty");
        return NO;
    }
    if (!_baseEndpointUrl.length) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthConfiguration.baseEndpointUrl property is empty");
        return NO;
    }
    if (![NSURL URLWithString:_baseEndpointUrl]) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthConfiguration.baseEndpointUrl is not valid URL");
        return NO;
    }
    if (_offlineAuthenticationCodeComponentLength < MIN_OFFLINE_AUTH_CODE_COMPONENT_LEN ||
        _offlineAuthenticationCodeComponentLength > MAX_OFFLINE_AUTH_CODE_COMPONENT_LEN) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"PowerAuthConfiguration.offlineAuthenticationCodeComponentLength property is out of range");
        return NO;
    }
    if (_sharingConfiguration && ![_sharingConfiguration validateConfiguration:error]) {
        return NO;
    }
    NSError * localError = nil;
    [PowerAuthCoreConfig validateConfiguration:_configuration
                                     algorithm:(PowerAuthCoreAlgorithm)_algorithm
                                         error:&localError];
    if (localError) {
        PA2WrapError(localError, error);
        return NO;
    }
    return YES;
}

- (id)copyWithZone:(NSZone *)zone
{
    PowerAuthConfiguration * c = [[self.class allocWithZone:zone] init];
    if (c) {
        c->_instanceId = _instanceId;
        c->_baseEndpointUrl = _baseEndpointUrl;
        c->_configuration = _configuration;
        c->_algorithm = _algorithm;
        c->_keychainKey_Biometry = _keychainKey_Biometry;
        c->_disableAutomaticProtocolUpgrade = _disableAutomaticProtocolUpgrade;
        c->_offlineAuthenticationCodeComponentLength = _offlineAuthenticationCodeComponentLength;
        c->_sharingConfiguration = [_sharingConfiguration copy];
    }
    return c;
}

// PA2_DEPRECATED(2.0.0)
- (void) setOfflineSignatureComponentLength:(NSUInteger)offlineSignatureComponentLength
{
    _offlineAuthenticationCodeComponentLength = offlineSignatureComponentLength;
}
// PA2_DEPRECATED(2.0.0)
- (NSUInteger) offlineSignatureComponentLength
{
    return _offlineAuthenticationCodeComponentLength;
}

// PA2_DEPRECATED(2.0.0)
- (void) setExternalEncryptionKey:(PowerAuthCoreData *)externalEncryptionKey
{
    if (externalEncryptionKey) {
        PowerAuthLog(@"WARNING: EEK is not supported in this version of SDK");
    }
}
// PA2_DEPRECATED(2.0.0)
- (PowerAuthCoreData*) externalEncryptionKey
{
    return nil;
}

@end
