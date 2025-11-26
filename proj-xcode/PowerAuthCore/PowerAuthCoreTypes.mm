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

#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace powerAuth;

@implementation PowerAuthCoreHttpHeader

- (instancetype) initWithHttpHeader:(const powerAuth::HttpHeader &)httpHeader
{
    self = [super init];
    if (self) {
        _headerName = cc7::objc::CopyToNSString(httpHeader.headerName);
        _headerValue = cc7::objc::CopyToNSString(httpHeader.headerValue);
    }
    return self;
}

@end

@implementation PowerAuthCoreDevicePublicKeyData

- (instancetype) initWithKeyData:(const powerAuth::DevicePublicKeyData&)keyData
{
    self = [super init];
    if (self) {
        _keyType = static_cast<PowerAuthCoreSignatureKeyType>(keyData.keyType);
        _keyAlgorithm = cc7::objc::CopyToNSString(keyData.keyAlgorithm);
        _keyData = cc7::objc::CopyToNSData(keyData.keyData);
    }
    return self;
}

@end
