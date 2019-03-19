/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2RestApiEndpoint.h"
#import "PA2RestApiObjects.h"

#define FL_SERIALIZED				(1 << 0)
#define FL_ALLOWED_IN_UPGRADE		(1 << 1)
#define IS_FLAG(v, f)				((v & f) == f)

@implementation PA2RestApiEndpoint
{
	NSUInteger _flags;
}

#pragma mark - Activation

+ (instancetype) createActivation
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/activation/create"
											request:[PA2CreateActivationRequest class]
										   response:[PA2CreateActivationResponse class]
										  encryptor:PA2EncryptorId_ActivationRequest
										  authUriId:nil];
}

+ (instancetype) getActivationStatus;
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/activation/status"
											request:[PA2GetActivationStatusRequest class]
										   response:[PA2GetActivationStatusResponse class]
										  encryptor:PA2EncryptorId_None
										  authUriId:nil];
}

+ (instancetype) removeActivation;
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/activation/remove"
											request:nil
										   response:nil
										  encryptor:PA2EncryptorId_None
										  authUriId:@"/pa/activation/remove"];
}

#pragma mark - Protocol upgrade

+ (instancetype) upgradeStartV3
{
	// Upgrade start requires serialization due to fact, that we don't want to start upgrade
	// concurrently with another signed request. The request is also allowed during the upgrade.
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/upgrade/start"
											request:nil
										   response:[PA2UpgradeStartV3Response class]
										  encryptor:PA2EncryptorId_UpgradeStart
										  authUriId:nil
											  flags:FL_SERIALIZED | FL_ALLOWED_IN_UPGRADE];
}

+ (instancetype) upgradeCommitV3
{
	// Upgrade commit requires signature, so it's serialized and also must be allowed
	// during the upgrade :)
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/upgrade/commit"
											request:nil
										   response:nil
										  encryptor:PA2EncryptorId_None
										  authUriId:@"/pa/upgrade/commit"
											  flags:FL_SERIALIZED | FL_ALLOWED_IN_UPGRADE];
}

#pragma mark - Tokens

+ (instancetype) getToken
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/token/create"
											request:nil
										   response:[PA2GetTokenResponse class]
										  encryptor:PA2EncryptorId_TokenCreate
										  authUriId:@"/pa/token/create"];
}

+ (instancetype) removeToken
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/token/remove"
											request:[PA2RemoveTokenRequest class]
										   response:nil
										  encryptor:PA2EncryptorId_None
										  authUriId:@"/pa/token/remove"];
}

#pragma mark - Other

+ (instancetype) validateSignature
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/signature/validate"
											request:nil
										   response:nil
										  encryptor:PA2EncryptorId_None
										  authUriId:@"/pa/signature/validate"];
}

+ (instancetype) vaultUnlock;
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/vault/unlock"
											request:[PA2VaultUnlockRequest class]
										   response:[PA2VaultUnlockResponse class]
										  encryptor:PA2EncryptorId_VaultUnlock
										  authUriId:@"/pa/vault/unlock"];
}

+ (instancetype) confirmRecoveryCode
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/recovery/confirm"
											request:[PA2ConfirmRecoveryCodeRequest class]
										   response:[PA2ConfirmRecoveryCodeResponse class]
										  encryptor:PA2EncryptorId_ConfirmRecoveryCode
										  authUriId:@"/pa/recovery/confirm"];
}

#pragma mark - Public getters

- (BOOL) isEncrypted
{
	return _encryptor != PA2EncryptorId_None;
}

- (BOOL) isSigned
{
	return _authUriId != nil;
}

- (BOOL) isSerialized
{
	return IS_FLAG(_flags, FL_SERIALIZED);
}

- (BOOL) isAvailableInProtocolUpgrade
{
	return IS_FLAG(_flags, FL_ALLOWED_IN_UPGRADE);
}


#pragma mark - Private constructors

- (id) initWithPath:(NSString*)path
			request:(Class)request
		   response:(Class)response
		  encryptor:(PA2EncryptorId)encryptor
		  authUriId:(NSString*)authUriId
{
	// Default flags setup is:
	//
	// 1. If endpoint needs signature, then it's serialized, but not allowed in upgrade.
	// 2. On opposite to that, not signed requests are not serialized, but allowed in upgrade.
	//
	NSUInteger flags = (authUriId != nil) ? FL_SERIALIZED : FL_ALLOWED_IN_UPGRADE;
	return [self initWithPath:path
					  request:request
					 response:response
					encryptor:encryptor
					authUriId:authUriId
						flags:flags];
}

- (id) initWithPath:(NSString*)path
			request:(Class)request
		   response:(Class)response
		  encryptor:(PA2EncryptorId)encryptor
		  authUriId:(NSString*)authUriId
			  flags:(NSUInteger)flags
{
	self = [super init];
	if (self) {
		_relativePath = path;
		_method = @"POST";
		_requestClass = request;
		_responseClass = response;
		_encryptor = encryptor;
		_authUriId = authUriId;
		_flags = flags;
	}
	return self;
}
@end
