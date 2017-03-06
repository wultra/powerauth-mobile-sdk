/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

#import "PA2CreateActivationResponse.h"

@implementation PA2CreateActivationResponse

- (instancetype)initWithDictionary:(NSDictionary *)dictionary {
    self = [super init];
    if (self) {
        _activationId						= [dictionary objectForKey:@"activationId"];
        _activationNonce					= [dictionary objectForKey:@"activationNonce"];
        _ephemeralPublicKey					= [dictionary objectForKey:@"ephemeralPublicKey"];
        _encryptedServerPublicKey			= [dictionary objectForKey:@"encryptedServerPublicKey"];
        _encryptedServerPublicKeySignature	= [dictionary objectForKey:@"encryptedServerPublicKeySignature"];
    }
    return self;
}

- (NSDictionary *)toDictionary {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    if (_activationId) {
        [dictionary setObject:_activationId forKey:@"activationId"];
    }
    if (_activationNonce) {
        [dictionary setObject:_activationNonce forKey:@"activationNonce"];
    }
    if (_ephemeralPublicKey) {
        [dictionary setObject:_ephemeralPublicKey forKey:@"ephemeralPublicKey"];
    }
    if (_encryptedServerPublicKey) {
        [dictionary setObject:_encryptedServerPublicKey forKey:@"encryptedServerPublicKey"];
    }
    if (_encryptedServerPublicKeySignature) {
        [dictionary setObject:_encryptedServerPublicKeySignature forKey:@"encryptedServerPublicKeySignature"];
    }
    return dictionary;
}

@end
