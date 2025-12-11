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
@import PowerAuthCore;

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

- (BOOL) validateConfiguration
{
    BOOL result = YES;
    result = result && (_instanceId.length > 0);
    result = result && (_baseEndpointUrl.length > 0);
    result = result && (_offlineAuthenticationCodeComponentLength >= MIN_OFFLINE_AUTH_CODE_COMPONENT_LEN &&
                        _offlineAuthenticationCodeComponentLength <= MAX_OFFLINE_AUTH_CODE_COMPONENT_LEN);
    if (_sharingConfiguration) {
        result = result && [_sharingConfiguration validateConfiguration];
    }
    result = result && [PowerAuthCoreConfig validateConfiguration:_configuration
                                                        algorithm:(PowerAuthCoreAlgorithm)_algorithm];
    return result;
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
        c->_externalEncryptionKey = _externalEncryptionKey;
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

@end
