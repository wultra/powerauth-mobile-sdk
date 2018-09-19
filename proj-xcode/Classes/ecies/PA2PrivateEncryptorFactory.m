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

#import "PA2PrivateEncryptorFactory.h"

@implementation PA2PrivateEncryptorFactory
{
	PA2Session * _session;
	NSData * _deviceRelatedKey;
}
- (instancetype) initWithSession:(PA2Session*)session
				deviceRelatedKey:(NSData*)deviceRelatedKey
{
	self = [super init];
	if (self) {
		_session = session;
		_deviceRelatedKey = deviceRelatedKey;
	}
	return self;
}


#pragma mark - Public encryptors

- (PA2ECIESEncryptor*) publicEncryptorForApplicationScope
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Application sh1:nil meta:YES];
}

- (PA2ECIESEncryptor*) publicEncryptorForActivationScope
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Activation sh1:nil meta:YES];
}


#pragma mark - Private, for SDK internals

- (PA2ECIESEncryptor*) encryptorForActivationRequest
{
	return [self publicEncryptorForApplicationScope];
}

- (PA2ECIESEncryptor*) encryptorForActivationPayload
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Application sh1:@"/pa/activation" meta:NO];
}

- (PA2ECIESEncryptor*) encryptorForMigrationStartRequest
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Activation sh1:@"/pa/migration" meta:YES];
}

- (PA2ECIESEncryptor*) encryptorForVaultUnlockRequest
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Activation sh1:@"/pa/vault/unlock" meta:YES];
}

- (PA2ECIESEncryptor*) encryptorForCreateTokenRequest
{
	return [self encryptorForScope:PA2ECIESEncryptorScope_Activation sh1:@"/pa/token/create" meta:YES];
}


#pragma mark - Private factory

- (PA2ECIESEncryptor*) encryptorForScope:(PA2ECIESEncryptorScope)scope
									 sh1:(NSString*)sharedInfo1
									meta:(BOOL)metaData
{
	// Prepare data required for encryptor construction
	NSString * activationId = nil;
	PA2SignatureUnlockKeys * unlockKeys = nil;
	if (scope == PA2ECIESEncryptorScope_Activation) {
		// For activation scope, also prepare activation ID and possession unlock key.
		activationId = _session.activationIdentifier;
		unlockKeys = [[PA2SignatureUnlockKeys alloc] init];
		unlockKeys.possessionUnlockKey = _deviceRelatedKey;
	}
	// Prepare the rest of information required for o
	NSData * sharedInfo1Data = [sharedInfo1 dataUsingEncoding:NSUTF8StringEncoding];
	NSString * applicationKey = _session.sessionSetup.applicationKey;
	// Now create the encryptor
	PA2ECIESEncryptor * encryptor = [_session eciesEncryptorForScope:scope
																keys:unlockKeys
														 sharedInfo1:sharedInfo1Data];
	if (metaData) {
		// And assign the associated metadata
		encryptor.associatedMetaData = [[PA2ECIESMetaData alloc] initWithApplicationKey:applicationKey
																   activationIdentifier:activationId];
	}
	return encryptor;
}

@end
