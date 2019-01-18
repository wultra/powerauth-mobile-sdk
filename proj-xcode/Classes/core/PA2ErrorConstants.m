/**
 * Copyright 2016 Wultra s.r.o.
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

#import "PA2ErrorConstants.h"

#pragma mark - Error codes

/** PowerAuth SDK error domain */
NSString *const PA2ErrorDomain					= @"PA2ErrorDomain";
NSString *const PA2ErrorInfoKey_AdditionalInfo	= @"PA2ErrorInfoKey_AdditionalInfo";
NSString *const PA2ErrorInfoKey_ResponseData	= @"PA2ErrorInfoKey_ResponseData";

/** Error code for error with network connectivity or download */
NSInteger const PA2ErrorCodeNetworkError				= 1;
NSInteger const PA2ErrorCodeSignatureError				= 2;
NSInteger const PA2ErrorCodeInvalidActivationState		= 3;
NSInteger const PA2ErrorCodeInvalidActivationData		= 4;
NSInteger const PA2ErrorCodeMissingActivation			= 5;
NSInteger const PA2ErrorCodeAuthenticationFailed		= 6;
NSInteger const PA2ErrorCodeActivationPending			= 7;
NSInteger const PA2ErrorCodeKeychain					= 8;
NSInteger const PA2ErrorCodeBiometryNotAvailable		= 9;
NSInteger const PA2ErrorCodeBiometryCancel				= 10;
NSInteger const PA2ErrorCodeOperationCancelled			= 11;
NSInteger const PA2ErrorCodeEncryption					= 12;
NSInteger const PA2ErrorCodeWrongParameter				= 13;
NSInteger const PA2ErrorCodeInvalidToken				= 14;
NSInteger const PA2ErrorCodeWatchConnectivity			= 15;
NSInteger const PA2ErrorCodeProtocolUpgrade				= 16;
NSInteger const PA2ErrorCodePendingProtocolUpgrade		= 17;
