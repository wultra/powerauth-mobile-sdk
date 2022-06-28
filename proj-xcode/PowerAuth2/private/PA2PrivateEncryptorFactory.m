/**
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

#import "PA2PrivateEncryptorFactory.h"
@import PowerAuthCore;

@implementation PA2PrivateEncryptorFactory
{
	id<PowerAuthCoreSessionProvider> _sessionProvider;
	NSData * _deviceRelatedKey;
}
- (instancetype) initWithSessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
						deviceRelatedKey:(NSData*)deviceRelatedKey
{
	self = [super init];
	if (self) {
		_sessionProvider = sessionProvider;
		_deviceRelatedKey = deviceRelatedKey;
	}
	return self;
}

- (PowerAuthCoreEciesEncryptor*) encryptorWithId:(PA2EncryptorId)encryptorId
{
	switch (encryptorId) {
		// Generic
		case PA2EncryptorId_GenericApplicationScope:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Application sh1:@"/pa/generic/application" meta:YES];
		case PA2EncryptorId_GenericActivationScope:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Activation sh1:@"/pa/generic/activation" meta:YES];
		// Private
		case PA2EncryptorId_ActivationRequest:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Application sh1:@"/pa/generic/application" meta:YES];
		case PA2EncryptorId_ActivationPayload:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Application sh1:@"/pa/activation" meta:NO];
		case PA2EncryptorId_UpgradeStart:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Activation sh1:@"/pa/upgrade" meta:YES];
		case PA2EncryptorId_VaultUnlock:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Activation sh1:@"/pa/vault/unlock" meta:YES];
		case PA2EncryptorId_TokenCreate:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Activation sh1:@"/pa/token/create" meta:YES];
		case PA2EncryptorId_ConfirmRecoveryCode:
			return [self encryptorForScope:PowerAuthCoreEciesEncryptorScope_Activation sh1:@"/pa/recovery/confirm" meta:YES];
		default:
			return nil;
	}
}

#pragma mark - Private factory

- (PowerAuthCoreEciesEncryptor*) encryptorForScope:(PowerAuthCoreEciesEncryptorScope)scope
											   sh1:(NSString*)sharedInfo1
											  meta:(BOOL)metaData
{
	return [_sessionProvider readTaskWithSession:^id _Nullable(PowerAuthCoreSession * _Nonnull session) {
		// Prepare data required for encryptor construction
		NSString * activationId = nil;
		PowerAuthCoreSignatureUnlockKeys * unlockKeys = nil;
		if (scope == PowerAuthCoreEciesEncryptorScope_Activation) {
			// For activation scope, also prepare activation ID and possession unlock key.
			activationId = session.activationIdentifier;
			unlockKeys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
			unlockKeys.possessionUnlockKey = _deviceRelatedKey;
		}
		// Prepare the rest of information required for o
		NSData * sharedInfo1Data = [sharedInfo1 dataUsingEncoding:NSUTF8StringEncoding];
		NSString * applicationKey = session.sessionSetup.applicationKey;
		// Now create the encryptor
		PowerAuthCoreEciesEncryptor * encryptor = [session eciesEncryptorForScope:scope
																			 keys:unlockKeys
																	  sharedInfo1:sharedInfo1Data];
		if (metaData) {
			// And assign the associated metadata
			encryptor.associatedMetaData = [[PowerAuthCoreEciesMetaData alloc] initWithApplicationKey:applicationKey
																				 activationIdentifier:activationId];
		}
		return encryptor;
	}];
}

@end