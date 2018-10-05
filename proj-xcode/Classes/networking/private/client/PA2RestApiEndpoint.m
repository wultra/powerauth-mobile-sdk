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


@implementation PA2RestApiEndpoint

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

#pragma mark - Migration

+ (instancetype) migrationStart
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/migration/start"
											request:nil
										   response:nil
										  encryptor:PA2EncryptorId_MigrationStart
										  authUriId:nil];
}

+ (instancetype) migrationCommit
{
	return [[PA2RestApiEndpoint alloc] initWithPath:@"/pa/v3/migration/commit"
											request:nil
										   response:nil
										  encryptor:PA2EncryptorId_None
										  authUriId:@"/pa/migration/commit"];
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

#pragma mark - Public getters

- (BOOL) isSerialized
{
	return _authUriId != nil;
}

- (BOOL) isEncrypted
{
	return _encryptor != PA2EncryptorId_None;
}

#pragma mark - Private constructor

- (id) initWithPath:(NSString*)path
			request:(Class)request
		   response:(Class)response
		  encryptor:(PA2EncryptorId)encryptor
		  authUriId:(NSString*)authUriId
{
	self = [super init];
	if (self) {
		_relativePath = path;
		_method = @"POST";
		_requestClass = request;
		_responseClass = response;
		_encryptor = encryptor;
		_authUriId = authUriId;
	}
	return self;
}

@end
