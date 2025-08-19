/*
 * Copyright 2025 Wultra s.r.o.
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

#include <PowerAuth/Credentials.h>

#import <PowerAuthCore/PowerAuthCoreCredentials.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace powerAuth;
using namespace cc7;

@implementation PowerAuthCoreCredentials
{
    CredentialsPtr _credentials;
}

- (instancetype) initWithCredentials:(CredentialsPtr)credentials
{
    self = [super init];
    if (self) {
        _credentials = credentials;
    }
    return self;
}

+ (nonnull PowerAuthCoreCredentials*) possession
{
    return [[PowerAuthCoreCredentials alloc] initWithCredentials:Credentials::possession()];
}

+ (nullable PowerAuthCoreCredentials*) knowledge:(nonnull PowerAuthCorePassword*)password
{
    return [[PowerAuthCoreCredentials alloc] initWithCredentials:Credentials::knowledge(password.passObjRef->passwordData())];
}

+ (nullable PowerAuthCoreCredentials*) biometry:(nonnull PowerAuthCoreData*)biometryKek
{
    return [[PowerAuthCoreCredentials alloc] initWithCredentials:Credentials::biometry(biometryKek.byteArrayRef)];
}

- (const CredentialsPtr&) credentialsRef
{
    return _credentials;
}

@end
