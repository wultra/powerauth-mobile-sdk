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

#import "PA2PrivateMacros.h"
#import "PA2ErrorConstants.h"

id PA2CastToImpl(id instance, Class desiredClass)
{
	if ([instance isKindOfClass:desiredClass]) {
		return instance;
	}
	return nil;
}

static NSString * _GetDefaultErrorDescription(NSInteger errorCode, NSString * message)
{
	if (message) {
		return message;	// Use message if it's already available.
	}
#define _CODE_DESC(ec, text) if (errorCode == ec) return text;
	_CODE_DESC(PA2ErrorCodeNetworkError, @"Network error")
	_CODE_DESC(PA2ErrorCodeSignatureError, @"Signature error")
	_CODE_DESC(PA2ErrorCodeInvalidActivationState, @"Invalid activation state")
	_CODE_DESC(PA2ErrorCodeInvalidActivationData, @"Invalid activation data")
	_CODE_DESC(PA2ErrorCodeMissingActivation, @"Missing activation")
	_CODE_DESC(PA2ErrorCodeActivationPending, @"Pending activation")
	_CODE_DESC(PA2ErrorCodeBiometryNotAvailable, @"Biometry is not supported or is unavailable")
	_CODE_DESC(PA2ErrorCodeBiometryCancel, @"User did cancel biometry authentication dialog")
	_CODE_DESC(PA2ErrorCodeBiometryFailed, @"Biometry authentication failed")
	_CODE_DESC(PA2ErrorCodeOperationCancelled, @"Operation was cancelled by SDK")
	_CODE_DESC(PA2ErrorCodeEncryption, @"General encryption failure")
	_CODE_DESC(PA2ErrorCodeWrongParameter, @"Invalid parameter provided to method")
	_CODE_DESC(PA2ErrorCodeInvalidToken, @"Invalid or unknown token")
	_CODE_DESC(PA2ErrorCodeWatchConnectivity, @"Watch connectivity error")
	_CODE_DESC(PA2ErrorCodeProtocolUpgrade, @"Protocol upgrade error")
	_CODE_DESC(PA2ErrorCodePendingProtocolUpgrade, @"Pending protocol ugprade, try later")
#undef _CODE_DESC
	return [NSString stringWithFormat:@"Unknown error %@", @(errorCode)];
}

NSError * PA2MakeError(NSInteger errorCode, NSString * message)
{
	NSDictionary * info = @{ NSLocalizedDescriptionKey:  _GetDefaultErrorDescription(errorCode, message)};
	return [NSError errorWithDomain:PA2ErrorDomain code:errorCode userInfo:info];
}
