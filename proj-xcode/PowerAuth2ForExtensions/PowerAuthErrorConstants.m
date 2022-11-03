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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForExtensions/PowerAuthErrorConstants.h>
#import "PA2PrivateConstants.h"

#pragma mark - Error codes

NSString *const PowerAuthErrorDomain                            = PA2Def_PowerAuthErrorDomain;
NSString *const PowerAuthErrorInfoKey_AdditionalInfo            = PA2Def_PowerAuthErrorInfoKey_AdditionalInfo;
NSString *const PowerAuthErrorInfoKey_ResponseData              = PA2Def_PowerAuthErrorInfoKey_ResponseData;
NSString *const PowerAuthErrorInfoKey_ExternalPendingOperation  = PA2Def_PowerAuthErrorInfoKey_ExtPendingApp;

NSString * PA2MakeDefaultErrorDescription(NSInteger errorCode, NSString * message)
{
    if (message) {
        return message; // Use message if it's already available.
    }
#define _CODE_DESC(ec, text) case ec: return text;
    switch (errorCode) {
        _CODE_DESC(PowerAuthErrorCode_NetworkError, @"Network error")
        _CODE_DESC(PowerAuthErrorCode_SignatureError, @"Signature error")
        _CODE_DESC(PowerAuthErrorCode_InvalidActivationState, @"Invalid activation state")
        _CODE_DESC(PowerAuthErrorCode_InvalidActivationCode, @"Invalid activation code")
        _CODE_DESC(PowerAuthErrorCode_InvalidActivationData, @"Invalid activation data")
        _CODE_DESC(PowerAuthErrorCode_MissingActivation, @"Missing activation")
        _CODE_DESC(PowerAuthErrorCode_ActivationPending, @"Pending activation")
        _CODE_DESC(PowerAuthErrorCode_BiometryNotAvailable, @"Biometry is not supported or is unavailable")
        _CODE_DESC(PowerAuthErrorCode_BiometryCancel, @"User did cancel biometry authentication dialog")
        _CODE_DESC(PowerAuthErrorCode_BiometryFailed, @"Biometry authentication failed")
        _CODE_DESC(PowerAuthErrorCode_OperationCancelled, @"Operation was cancelled by SDK")
        _CODE_DESC(PowerAuthErrorCode_Encryption, @"General encryption failure")
        _CODE_DESC(PowerAuthErrorCode_WrongParameter, @"Invalid parameter provided to method")
        _CODE_DESC(PowerAuthErrorCode_InvalidToken, @"Invalid or unknown token")
        _CODE_DESC(PowerAuthErrorCode_WatchConnectivity, @"Watch connectivity error")
        _CODE_DESC(PowerAuthErrorCode_ProtocolUpgrade, @"Protocol upgrade error")
        _CODE_DESC(PowerAuthErrorCode_PendingProtocolUpgrade, @"Pending protocol ugprade, try later")
        _CODE_DESC(PowerAuthErrorCode_ExternalPendingOperation, @"Other application does critical operation")
        default:
            return [NSString stringWithFormat:@"Unknown error %@", @(errorCode)];
    }
#undef _CODE_DESC
}

NSError * PA2MakeError(NSInteger errorCode, NSString * message)
{
    NSDictionary * info = @{ NSLocalizedDescriptionKey: PA2MakeDefaultErrorDescription(errorCode, message)};
    return [NSError errorWithDomain:PowerAuthErrorDomain code:errorCode userInfo:info];
}

NSError * PA2MakeErrorInfo(NSInteger errorCode, NSString * message, NSDictionary * info)
{
    NSMutableDictionary * mutableInfo = info ? [info mutableCopy] : [NSMutableDictionary dictionary];
    mutableInfo[NSLocalizedDescriptionKey] = PA2MakeDefaultErrorDescription(errorCode, message);
    return [NSError errorWithDomain:PowerAuthErrorDomain code:errorCode userInfo:mutableInfo];
}

#pragma mark - NSError extension

@implementation NSError (PowerAuthErrorCode)

- (PowerAuthErrorCode) powerAuthErrorCode
{
    if ([self.domain isEqualToString:PowerAuthErrorDomain]) {
        return (PowerAuthErrorCode)self.code;
    }
    return PowerAuthErrorCode_NA;
}

- (PowerAuthExternalPendingOperation*) powerAuthExternalPendingOperation
{
    if ([self.domain isEqualToString:PowerAuthErrorDomain]) {
        return self.userInfo[PowerAuthErrorInfoKey_ExternalPendingOperation];
    }
    return nil;
}

@end
