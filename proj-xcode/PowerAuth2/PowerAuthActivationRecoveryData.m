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

#import <PowerAuth2/PowerAuthActivationRecoveryData.h>

@import PowerAuthCore;

@implementation PowerAuthActivationRecoveryData
{
    PowerAuthCoreRecoveryData * _recoveryData;
}

- (instancetype) initWithRecoveryData:(PowerAuthCoreRecoveryData*)recoveryData
{
    self = [super init];
    if (self) {
        _recoveryData = recoveryData;
    }
    return self;
}

- (NSString*) recoveryCode
{
    return _recoveryData.recoveryCode;
}

- (NSString*) puk
{
    return _recoveryData.puk;
}

#ifdef DEBUG
- (NSString*) description
{
    NSString * rc = _recoveryData.recoveryCode ? _recoveryData.recoveryCode : @"<null>";
    NSString * puk = _recoveryData.puk ? _recoveryData.puk : @"<null>";
    return [NSString stringWithFormat:@"<PowerAuthActivationRecoveryData code=%@, puk=%@>", rc, puk];
}
#endif

@end
