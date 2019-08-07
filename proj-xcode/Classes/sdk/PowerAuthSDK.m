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

#import "PowerAuthSDK+Private.h"

#import "PA2Keychain.h"
#import "PA2OtpUtil.h"

#import "PA2HttpClient.h"
#import "PA2RestApiObjects.h"
#import "PA2AsyncOperation.h"
#import "PA2ObjectSerialization.h"

#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateHttpTokenProvider.h"
#import "PA2PrivateMacros.h"
#import "PA2WCSessionManager+Private.h"
#import "PA2PrivateEncryptorFactory.h"
#import "PA2GetActivationStatusTask.h"

#import <UIKit/UIKit.h>

#pragma mark - Constants

/** In case a config is missing, exception with this identifier is thrown. */
NSString *const PA2ExceptionMissingConfig		= @"PA2ExceptionMissingConfig";

#pragma mark - PowerAuth SDK implementation

@implementation PowerAuthSDK
{
	id<NSLocking> _lock;
	
	PowerAuthConfiguration * _configuration;
	PA2KeychainConfiguration * _keychainConfiguration;
	PA2ClientConfiguration * _clientConfiguration;
	
	PA2HttpClient *_client;
	NSString *_biometryKeyIdentifier;
	PA2Keychain *_statusKeychain;
	PA2Keychain *_sharedKeychain;
	PA2Keychain *_biometryOnlyKeychain;
	PA2PrivateHttpTokenProvider * _remoteHttpTokenProvider;
	
	/// Current pending status task.
	PA2GetActivationStatusTask * _getStatusTask;
}

#pragma mark - Private methods

- (void) initializeWithConfiguration:(PowerAuthConfiguration*)configuration
			   keychainConfiguration:(PA2KeychainConfiguration*)keychainConfiguration
				 clientConfiguration:(PA2ClientConfiguration*)clientConfiguration
{
	
	// Check if the configuration was nil
	if (configuration == nil) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
	
	// Validate that the configuration was set up correctly
	if (![configuration validateConfiguration]) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
	
	// Exclusive lock
	_lock = [[NSLock alloc] init];
	
	// Make copy of configuration objects
	_configuration = [configuration copy];
	_keychainConfiguration = [(keychainConfiguration ? keychainConfiguration : [PA2KeychainConfiguration sharedInstance]) copy];
	_clientConfiguration = [(clientConfiguration ? clientConfiguration : [PA2ClientConfiguration sharedInstance]) copy];
	
	// Prepare identifier for biometry related keys - use instanceId by default, or a custom value if set
	_biometryKeyIdentifier = _configuration.keychainKey_Biometry ? _configuration.keychainKey_Biometry : _configuration.instanceId;
	
	// Create session setup parameters
	PA2SessionSetup *setup = [[PA2SessionSetup alloc] init];
	setup.applicationKey = _configuration.appKey;
	setup.applicationSecret = _configuration.appSecret;
	setup.masterServerPublicKey = _configuration.masterServerPublicKey;
	setup.externalEncryptionKey = _configuration.externalEncryptionKey;
	
	// Create a new session
	_session = [[PA2Session alloc] initWithSessionSetup:setup];
	if (_session == nil) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
	
	// Create and setup a new client
	_client = [[PA2HttpClient alloc] initWithConfiguration:_clientConfiguration
										   completionQueue:dispatch_get_main_queue()
												   baseUrl:_configuration.baseEndpointUrl
													helper:self];
	
	// Create a new keychain instances
	_statusKeychain			= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Status
													accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_sharedKeychain			= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Possession
													accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_biometryOnlyKeychain	= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Biometry];
	// Initialize token store with its own keychain as a backing storage and remote token provider.
	PA2Keychain * tokenStoreKeychain = [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_TokenStore
																   accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_remoteHttpTokenProvider = [[PA2PrivateHttpTokenProvider alloc] initWithHttpClient:_client];
	_tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:self.configuration
																	 keychain:tokenStoreKeychain
															   statusProvider:_session
															   remoteProvider:_remoteHttpTokenProvider];

	// Make sure to reset keychain data after app re-install.
	// Important: This deletes all Keychain data in all PowerAuthSDK instances!
	// By default, the code uses standard user defaults, use `PA2KeychainConfiguration.keychainAttribute_UserDefaultsSuiteName` to use `NSUserDefaults` with a custom suite name.
	NSUserDefaults *userDefaults = nil;
	if (_keychainConfiguration.keychainAttribute_UserDefaultsSuiteName != nil) {
		userDefaults = [[NSUserDefaults alloc] initWithSuiteName:_keychainConfiguration.keychainAttribute_UserDefaultsSuiteName];
	} else {
		userDefaults = [NSUserDefaults standardUserDefaults];
	}
	if ([userDefaults boolForKey:PA2Keychain_Initialized] == NO) {
		[_statusKeychain deleteAllData];
		[_sharedKeychain deleteAllData];
		[_biometryOnlyKeychain deleteAllData];
		[tokenStoreKeychain deleteAllData];
		[userDefaults setBool:YES forKey:PA2Keychain_Initialized];
		[userDefaults synchronize];
	}
	
	// Attempt to restore session state
	[self restoreState];
	
	// Register this instance to handle messages
	[[PA2WCSessionManager sharedInstance] registerDataHandler:self];
}

- (void) dealloc
{
	// Unregister this instance for processing packets...
	[[PA2WCSessionManager sharedInstance] unregisterDataHandler:self];
	// Cancel possible get activation status task
	[self cancelActivationStatusTask];
}


+ (void) throwInvalidConfigurationException {
	[NSException raise:PA2ExceptionMissingConfig
				format:@"Invalid PowerAuthSDK configuration. You must set a valid PowerAuthConfiguration to PowerAuthSDK instance using initializer."];
}

- (PowerAuthConfiguration*) configuration
{
	return [_configuration copy];
}

- (PA2ClientConfiguration*) clientConfiguration
{
	return [_clientConfiguration copy];
}

- (PA2KeychainConfiguration*) keychainConfiguration
{
	return [_keychainConfiguration copy];
}

- (NSString*) privateInstanceId
{
	// Private getter, used inside the IOS-SDK
	return _configuration.instanceId;
}

/**
 This private method checks for valid PA2SessionSetup and throws a PA2ExceptionMissingConfig exception when the provided configuration
 is not correct or is missing.
 */
- (void) checkForValidSetup
{
	if (!_session.hasValidSetup) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
}

#pragma mark - Key management

- (NSData*) deviceRelatedKey
{
	// Cache the possession key in the keychain
	NSData * possessionKey = [_sharedKeychain dataForKey:_keychainConfiguration.keychainKey_Possession status:nil];
	if (nil == possessionKey) {
		NSString *uuidString;
#if TARGET_IPHONE_SIMULATOR
		uuidString = @"ffa184f9-341a-444f-8495-de04d0d490be";
#else
		uuidString = [UIDevice currentDevice].identifierForVendor.UUIDString;
#endif
		NSData *uuidData = [uuidString dataUsingEncoding:NSUTF8StringEncoding];
		possessionKey = [PA2Session normalizeSignatureUnlockKeyFromData:uuidData];
		[_sharedKeychain addValue:possessionKey forKey:_keychainConfiguration.keychainKey_Possession];
	}
	return possessionKey;
}

- (NSData*) biometryRelatedKeyUserCancelled:(nullable BOOL *)userCancelled prompt:(NSString*)prompt {
	if ([_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier]) {
		OSStatus status;
		NSData *key = [_biometryOnlyKeychain dataForKey:_biometryKeyIdentifier status:&status prompt:prompt];
		if (userCancelled != NULL) {
			if (status == errSecUserCanceled) {
				*userCancelled = YES;
			} else {
				*userCancelled = NO;
			}
		}
		return key;
	} else {
		return nil;
	}
}

- (PA2SignatureUnlockKeys*) signatureKeysForAuthentication:(PowerAuthAuthentication*)authentication
											 userCancelled:(nonnull BOOL *)userCancelled
{
	// Generate signature key encryption keys
	NSData *possessionKey = nil;
	NSData *biometryKey = nil;
	PA2Password *knowledgeKey = nil;
	if (authentication.usePossession) {
		if (authentication.overridenPossessionKey) {
			possessionKey = authentication.overridenPossessionKey;
		} else {
			possessionKey = [self deviceRelatedKey];
		}
	}
	if (authentication.useBiometry) {
		if (authentication.overridenBiometryKey) { // user specified a custom biometry key
			biometryKey = authentication.overridenBiometryKey;
		} else { // default biometry key should be fetched
			biometryKey = [self biometryRelatedKeyUserCancelled:userCancelled prompt:authentication.biometryPrompt];
			if (*userCancelled) {
				return nil;
			}
			// If the key was not fetched (and not because of user cancel action) and biometry
			// was requested, generate a "fake key" so that signature can silently fail
			else {
				if (biometryKey == nil) {
					PA2Log(@"ERROR! Biometric authentication failed or there's no biometric key in the keychain.");
					biometryKey = [PA2Session generateSignatureUnlockKey];
				}
			}
		}
	}
	if (authentication.usePassword) {
		knowledgeKey = [PA2Password passwordWithString:authentication.usePassword];
	}
	
	// Prepare signature unlock keys structure
	PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
	keys.possessionUnlockKey = possessionKey;
	keys.biometryUnlockKey = biometryKey;
	keys.userPassword = knowledgeKey;
	return keys;
}

- (PA2SignatureFactor) determineSignatureFactorForAuthentication:(PowerAuthAuthentication*)authentication
{
	PA2SignatureFactor factor = 0;
	if (authentication.usePossession) {
		factor |= PA2SignatureFactor_Possession;
	}
	if (authentication.usePassword != nil) {
		factor |= PA2SignatureFactor_Knowledge;
	}
	if (authentication.useBiometry) {
		factor |= PA2SignatureFactor_Biometry;
	}
	return factor;
}

- (id<PA2OperationTask>) fetchEncryptedVaultUnlockKey:(PowerAuthAuthentication*)authentication
											   reason:(PA2VaultUnlockReason)reason
											 callback:(void(^)(NSString * encryptedEncryptionKey, NSError *error))callback
{
	[self checkForValidSetup];
	// Check if there is an activation present
	if (!_session.hasValidActivation) {
		callback(nil, PA2MakeError(PA2ErrorCodeMissingActivation, nil));
		return nil;
	}
	return [_client postObject:[[PA2VaultUnlockRequest alloc] initWithReason:reason]
							to:[PA2RestApiEndpoint vaultUnlock]
						  auth:authentication
					completion:^(PA2RestResponseStatus status, id<PA2Decodable> response, NSError *error) {
						NSString * encryptedEncryptionKey = nil;
						if (status == PA2RestResponseStatus_OK) {
							PA2VaultUnlockResponse * ro = response;
							encryptedEncryptionKey = ro.encryptedVaultEncryptionKey;
						}
						if (!encryptedEncryptionKey && !error) {
							// fallback to error
							error = PA2MakeError(PA2ErrorCodeInvalidActivationState, nil);
						}
						callback(encryptedEncryptionKey, error);
					}];
}

#pragma mark - Public methods

#pragma mark Initializers and SDK instance getters

static PowerAuthSDK * s_inst;

- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
						  keychainConfiguration:(nullable PA2KeychainConfiguration *)keychainConfiguration
							clientConfiguration:(nullable PA2ClientConfiguration *)clientConfiguration
{
	self = [super init];
	if (self) {
		[self initializeWithConfiguration:configuration
					keychainConfiguration:keychainConfiguration
					  clientConfiguration:clientConfiguration];
	}
	return self;
}

- (instancetype)initWithConfiguration:(PowerAuthConfiguration *)configuration
{
	return [self initWithConfiguration:configuration keychainConfiguration:nil clientConfiguration:nil];
}

+ (void) initSharedInstance:(PowerAuthConfiguration*)configuration
{
	[self initSharedInstance:configuration keychainConfiguration:nil clientConfiguration:nil];
}

+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration
	  keychainConfiguration:(nullable PA2KeychainConfiguration *)keychainConfiguration
		clientConfiguration:(nullable PA2ClientConfiguration *)clientConfiguration
{
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		s_inst = [[PowerAuthSDK alloc] initWithConfiguration:configuration
									   keychainConfiguration:keychainConfiguration
										 clientConfiguration:clientConfiguration];
	});
}

+ (PowerAuthSDK*) sharedInstance
{
	if (!s_inst) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
	return s_inst;
}

#pragma mark Session state management

- (BOOL) restoreState
{
	NSData *sessionData = [_statusKeychain dataForKey:_configuration.instanceId status:nil];
	if (sessionData) {
		[_session resetSession];
		return [_session deserializeState:sessionData];
	} else {
		return NO;
	}
}

- (void) saveSessionState
{
	[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
}

- (BOOL) canStartActivation
{
	[self checkForValidSetup];
	return _session.canStartActivation;
}

- (BOOL) hasPendingActivation
{
	[self checkForValidSetup];
	return _session.hasPendingActivation;
}

- (BOOL) hasValidActivation
{
	[self checkForValidSetup];
	return _session.hasValidActivation;
}

- (BOOL) hasPendingProtocolUpgrade
{
	[self checkForValidSetup];
	return _session.hasPendingProtocolUpgrade;
}


#pragma mark - Activation
#pragma mark Creating a new activation

- (id<PA2OperationTask>) createActivationWithName:(NSString*)name
								   activationCode:(NSString*)activationCode
										 callback:(void(^)(PA2ActivationResult *result, NSError *error))callback
{
	return [self createActivationWithName:name activationCode:activationCode extras:nil callback:callback];
}

- (id<PA2OperationTask>) createActivationWithName:(NSString*)name
								   activationCode:(NSString*)activationCode
										   extras:(NSString*)extras
										 callback:(void(^)(PA2ActivationResult *result, NSError *error))callback
{
	// Validate activation code
	PA2Otp * otp = [PA2OtpUtil parseFromActivationCode:activationCode];
	if (!otp) {
		// Invalid activation code
		callback(nil, PA2MakeError(PA2ErrorCodeInvalidActivationData, nil));
		return nil;
	}
	// Now create request & call private function
	PA2CreateActivationRequest * request = [PA2CreateActivationRequest standardActivationWithCode:otp.activationCode];
	return [self createActivationWithName:name
								  request:request
									  otp:otp
								   extras:extras
								 callback:callback];
}

- (id<PA2OperationTask>) createActivationWithName:(NSString*)name
							   identityAttributes:(NSDictionary<NSString*,NSString*>*)identityAttributes
										   extras:(NSString*)extras
										 callback:(void(^)(PA2ActivationResult * result, NSError * error))callback
{
	PA2CreateActivationRequest * request = [PA2CreateActivationRequest customActivationWithIdentityAttributes:identityAttributes];
	return [self createActivationWithName:name
								  request:request
									  otp:nil
								   extras:extras
								 callback:callback];
}

- (nullable id<PA2OperationTask>) createActivationWithName:(nullable NSString*)name
											  recoveryCode:(nonnull NSString*)recoveryCode
													   puk:(nonnull NSString*)puk
													extras:(nullable NSString*)extras
												  callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback
{
	// Validate recovery code & PUK
	BOOL validPUK = [PA2OtpUtil validateRecoveryPuk:puk];
	PA2Otp * otp = [PA2OtpUtil parseFromRecoveryCode:recoveryCode];
	if (!otp || !validPUK) {
		// Invalid input data
		callback(nil, PA2MakeError(PA2ErrorCodeInvalidActivationData, nil));
		return nil;
	}
	// Now create an activation creation request
	PA2CreateActivationRequest * request = [PA2CreateActivationRequest recoveryActivationWithCode:otp.activationCode puk:puk];
	return [self createActivationWithName:name
								  request:request
									  otp:nil
								   extras:extras
								 callback:callback];
}

#pragma mark Commit

- (BOOL) commitActivationWithPassword:(NSString*)password
								error:(NSError**)error
{
	PowerAuthAuthentication *authentication = [[PowerAuthAuthentication alloc] init];
	authentication.useBiometry = YES;
	authentication.usePossession = YES;
	authentication.usePassword = password;
	return [self commitActivationWithAuthentication:authentication error:error];
}

- (BOOL) commitActivationWithAuthentication:(PowerAuthAuthentication*)authentication
									  error:(NSError**)error
{
	
	[self checkForValidSetup];
	
	// Check if there is a pending activation present and not an already existing valid activation
	if (!_session.hasPendingActivation) {
		if (error) {
			*error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationState userInfo:nil];
		}
		return NO;
	}
	
	// Prepare key encryption keys
	NSData *possessionKey = nil;
	NSData *biometryKey = nil;
	PA2Password *knowledgeKey = nil;
	if (authentication.usePossession) {
		possessionKey = [self deviceRelatedKey];
	}
	if (authentication.useBiometry) {
		biometryKey = [PA2Session generateSignatureUnlockKey];
	}
	if (authentication.usePassword) {
		knowledgeKey = [PA2Password passwordWithString:authentication.usePassword];
	}
	
	// Prepare signature unlock keys structure
	PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
	keys.possessionUnlockKey = possessionKey;
	keys.biometryUnlockKey = biometryKey;
	keys.userPassword = knowledgeKey;
	
	// Complete the activation
	BOOL result = [_session completeActivation:keys];
	
	// Propagate error
	if (!result && error) {
		*error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationState userInfo:nil];
	}
	
	// Store keys and session state in Keychain
	if (result) {
		[_statusKeychain deleteDataForKey:_configuration.instanceId];
		[_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
		
		[_statusKeychain addValue:_session.serializedState forKey:_configuration.instanceId];
		if (biometryKey) {
			[_biometryOnlyKeychain addValue:biometryKey forKey:_biometryKeyIdentifier useBiometry:YES];
		}
	}
	
	// Return result
	return result;
}

- (NSString*) activationIdentifier
{
	return _session.activationIdentifier;
}

- (NSString*) activationFingerprint
{
	return _session.activationFingerprint;
}


#pragma mark Private activation

/**
 Private method for activation creation
 */
- (id<PA2OperationTask>) createActivationWithName:(NSString*)name
										  request:(PA2CreateActivationRequest*)request
											  otp:(PA2Otp*)otp
										   extras:(NSString*)extras
										 callback:(void(^)(PA2ActivationResult * result, NSError * error))callback
{
	[self checkForValidSetup];
	
	// Check if activation may be started
	if (![self canStartActivation]) {
		callback(nil, PA2MakeError(PA2ErrorCodeInvalidActivationState, nil));
		return nil;
	}
	
	PA2CreateActivationRequestData * requestData = [[PA2CreateActivationRequestData alloc] init];
	requestData.activationName = name;
	requestData.extras = extras;
	
	NSError * error = nil;
	PA2ECIESEncryptor * decryptor = [self prepareActivationRequest:request
													   requestData:requestData
															   otp:otp
															 error:&error];
	if (!decryptor) {
		callback(nil, error);
		return nil;
	}
	
	// Now it's everything prepared for sending the request
	return [_client postObject:request
							to:[PA2RestApiEndpoint createActivation]
						  auth:nil
					completion:^(PA2RestResponseStatus status, id<PA2Decodable> response, NSError *error) {
						// HTTP request completion
						PA2ActivationResult * result = nil;
						if (status == PA2RestResponseStatus_OK) {
							// Validate response from the server
							result = [self validateActivationResponse:response
															decryptor:decryptor
																error:&error];
						}
						if (!result && !error) {
							// Fallback, to produce at least some error
							error = PA2MakeError(PA2ErrorCodeInvalidActivationData, nil);
						}
						if (error) {
							[_session resetSession];
						}
						// Now call back to the application
						callback(result, error);
						
					} cancel:^{
						// In case of cancel, we need to reset the session. The reset itself is
						// thread safe, but it's good to issue that to the main thread.
						dispatch_async(dispatch_get_main_queue(), ^{
							[_session resetSession];
						});
					}];
}

/**
 Private method starts an activation.
 
 The method requires request & request data and if everything's right, then request.activationData
 is prepared and metods returns a new decryptor, required for response decryption.
 */
- (PA2ECIESEncryptor*) prepareActivationRequest:(PA2CreateActivationRequest*)request
									requestData:(PA2CreateActivationRequestData*)requestData
											otp:(PA2Otp*)otp
										  error:(NSError**)error
{
	PA2ECIESEncryptor * decryptor = nil;
	NSError * localError = nil;
	
	// Prepare data for low level code. Note that "otp" is optional and may be nil.
	PA2ActivationStep1Param * paramStep1 = [[PA2ActivationStep1Param alloc] init];
	paramStep1.activationCode = otp;

	// Begin with the activation
	PA2ActivationStep1Result * resultStep1 = [_session startActivation:paramStep1];
	if (resultStep1) {
		// Keep device's public key in requestData
		requestData.devicePublicKey = resultStep1.devicePublicKey;

		// Now we need to ecrypt request data with the Layer2 encryptor.
		PA2PrivateEncryptorFactory * factory = [[PA2PrivateEncryptorFactory alloc] initWithSession:_session deviceRelatedKey:[self deviceRelatedKey]];
		PA2ECIESEncryptor * privateEncryptor = [factory encryptorWithId:PA2EncryptorId_ActivationPayload];
		
		// Encrypt payload and put it directly to the request object.
		request.activationData = [PA2ObjectSerialization encryptObject:requestData
															 encryptor:privateEncryptor
																 error:&localError];
		if (!localError) {
			decryptor = privateEncryptor;
		}
	} else {
		localError = PA2MakeError(PA2ErrorCodeInvalidActivationData, nil);
	}
	// Return result & error
	if (error) {
		*error = localError;
	}
	return decryptor;
}

/**
 Private method validates response received from the server.
 In case of success, returns a full activation result object.
 */
- (PA2ActivationResult*) validateActivationResponse:(PA2CreateActivationResponse*)response
										  decryptor:(PA2ECIESEncryptor*)decryptor
											  error:(NSError**)error
{
	PA2ActivationResult * result = nil;
	NSError * localError = nil;
	PA2CreateActivationResponseData * responseData = [PA2ObjectSerialization decryptObject:response.activationData
																				  forClass:[PA2CreateActivationResponseData class]
																				 decryptor:decryptor
																					 error:&localError];
	if (responseData) {
		// Validate response from the server
		PA2ActivationStep2Param * paramStep2 = [[PA2ActivationStep2Param alloc] init];
		paramStep2.activationId = responseData.activationId;
		paramStep2.serverPublicKey = responseData.serverPublicKey;
		paramStep2.ctrData = responseData.ctrData;
		PA2ActivationRecoveryData * activationRecoveryData = nil;
		if (responseData.activationRecovery) {
			PA2RecoveryData * recoveryData = [[PA2RecoveryData alloc] init];
			recoveryData.recoveryCode = responseData.activationRecovery.recoveryCode;
			recoveryData.puk = responseData.activationRecovery.puk;
			paramStep2.activationRecovery = recoveryData;
			activationRecoveryData = [[PA2ActivationRecoveryData alloc] initWithRecoveryData:recoveryData];
		}
		PA2ActivationStep2Result * resultStep2 = [_session validateActivationResponse:paramStep2];
		if (resultStep2) {
			// Everything looks OK, we can construct result object.
			result = [[PA2ActivationResult alloc] init];
			result.activationFingerprint = resultStep2.activationFingerprint;
			result.customAttributes = response.customAttributes;
			result.activationRecovery = activationRecoveryData;
		} else {
			localError = PA2MakeError(PA2ErrorCodeInvalidActivationData, nil);
		}
	}
	// Return result & error
	if (error) {
		*error = localError;
	}
	return result;
}


#pragma mark Getting activations state

- (id<PA2OperationTask>) fetchActivationStatusWithCallback:(void(^)(PA2ActivationStatus *status, NSDictionary *customObject, NSError *error))callback
{
	[self checkForValidSetup];
	
	// Check for activation
	if (!_session.hasValidActivation) {
		NSInteger errorCode = _session.hasPendingActivation ? PA2ErrorCodeActivationPending : PA2ErrorCodeMissingActivation;
		callback(nil, nil, PA2MakeError(errorCode, nil));
		return nil;
	}
	// Create child task and add it to the status fetcher.
	PA2GetActivationStatusChildTask * task = [[PA2GetActivationStatusChildTask alloc] initWithCompletionQueue:dispatch_get_main_queue() completion:callback];
	[self getActivationStatusWithChildTask:task];
	return task;
}


- (void) getActivationStatusWithChildTask:(PA2GetActivationStatusChildTask*)childTask
{
	PA2GetActivationStatusTask * oldTask = nil;
	[_lock lock];
	{
		if (_getStatusTask) {
			if ([_getStatusTask addChildTask:childTask] == NO) {
				// unable to add child task. This means that current task is going to finish its execution soon,
				// so we need to create a new one.
				oldTask = _getStatusTask;
				_getStatusTask = nil;
			}
		}
		if (!_getStatusTask) {
			// Task doesn't exist. We need to create a new one.
			__weak PowerAuthSDK * weakSelf = self;
			_getStatusTask = [[PA2GetActivationStatusTask alloc] initWithHttpClient:_client
																   deviceRelatedKey:[self deviceRelatedKey]
																			session:_session
																	  sessionChange:^(PA2Session * session) {
																		  [weakSelf saveSessionState];
																	  } completion:^(PA2GetActivationStatusTask * task, PA2ActivationStatus* status, NSDictionary* customObject, NSError* error) {
																		  [weakSelf completeActivationStatusTask:task status:status customObject:customObject error:error];
																	  }];
			_getStatusTask.disableUpgrade = _configuration.disableAutomaticProtocolUpgrade;
			[_getStatusTask addChildTask:childTask];
			[_getStatusTask execute];
		}
	}
	[_lock unlock];
	
	if (oldTask) {
		// This is the reference to task which is going to finish its execution soon.
		// The ivar no longer holds the reference to the task, but we should keep that reference
		// for a little bit longer, to guarantee, that we don't destroy that object during its
		// finalization stage.
		[[NSOperationQueue mainQueue] addOperationWithBlock:^{
			// The following call does nothing, because the old task is no longer stored
			// in the `_getStatusTask` ivar. It just guarantees that the object will be alive
			// during waiting to execute the operation block.
			[self completeActivationStatusTask:oldTask status:nil customObject:nil error:nil];
		}];
	}
}


/**
 Completes pending PA2GetActivationStatusTask. The function resets internal `_getStatusTask` ivar,
 but only if it equals to provided "task" object.
 
 @param task task being completed
 */
- (void) completeActivationStatusTask:(PA2GetActivationStatusTask*)task
							   status:(PA2ActivationStatus*)status
						 customObject:(NSDictionary*)customObject
								error:(NSError*)error
{
	[_lock lock];
	{
		BOOL updateObjects;
		if (task == _getStatusTask) {
			// Regular processing, only one task was scheduled and it just finished.
			_getStatusTask = nil;
			updateObjects = YES;
		} else {
			// If _getStatusTask is nil, then it menas that last status task has been cancelled.
			// In this case, we should not update the objects.
			// If there's a different PA2GetActivationStatusTask object, then that means
			// that during the finishing our batch, was scheduled the next one. In this situation
			// we still can keep the last received objects, because there was no cancel, or reset.
			updateObjects = _getStatusTask != nil;
		}
		// Update last received objects
		if (!error && status && updateObjects) {
			_lastFetchedActivationStatus = status;
			_lastFetchedCustomObject = customObject;
		}
	}
	[_lock unlock];
}


/**
 Cancels possible pending PA2GetActivationStatusTask. The function can be called only in rare cases,
 like when SDK object is going to reset its local state.
 */
- (void) cancelActivationStatusTask
{
	[_lock lock];
	{
		[_getStatusTask cancel];
		_getStatusTask = nil;
		_lastFetchedActivationStatus = nil;
		_lastFetchedCustomObject = nil;
	}
	[_lock unlock];
}


#pragma mark Removing an activation

- (id<PA2OperationTask>) removeActivationWithAuthentication:(PowerAuthAuthentication*)authentication
												   callback:(void(^)(NSError *error))callback
{
	[self checkForValidSetup];
	return [_client postObject:nil
							to:[PA2RestApiEndpoint removeActivation]
						  auth:authentication
					completion:^(PA2RestResponseStatus status, id<PA2Decodable> response, NSError *error) {
						// Network communication completed correctly
						if (status == PA2RestResponseStatus_OK) {
							[self removeActivationLocal];
						}
						callback(error);
					}];
}

- (void) removeActivationLocal
{
	[self checkForValidSetup];
	BOOL error = NO;
	if ([_statusKeychain containsDataForKey:_configuration.instanceId]) {
		error = error || ![_statusKeychain deleteDataForKey:_configuration.instanceId];
	}
	if ([_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier]) {
		error = error || ![_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
	}
	if (error) {
		PA2Log(@"Removing activaton data from keychain failed. We can't recover from this error.");
	}
	[self cancelActivationStatusTask];
	[_tokenStore removeAllLocalTokens];
	[_session resetSession];
}


#pragma mark - Computing signatures

- (PA2AuthorizationHttpHeader*) requestGetSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
																uriId:(NSString*)uriId
															   params:(NSDictionary<NSString*, NSString*>*)params
																error:(NSError**)error
{
	NSData *data = [_session prepareKeyValueDictionaryForDataSigning:params];
	return [self requestSignatureWithAuthentication:authentication
											 method:@"GET"
											  uriId:uriId
											   body:data
											  error:error];
}

- (PA2AuthorizationHttpHeader*) requestSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
															method:(NSString*)method
															 uriId:(NSString*)uriId
															  body:(NSData*)body
															 error:(NSError**)error
{
	if (self.hasPendingProtocolUpgrade) {
		if (error) *error = PA2MakeError(PA2ErrorCodePendingProtocolUpgrade, @"Data signing is temporarily unavailable, due to pending protocol upgrade.");
		return nil;
	}
	PA2HTTPRequestData * requestData = [[PA2HTTPRequestData alloc] init];
	requestData.body = body;
	requestData.method = method;
	requestData.uri = uriId;
	PA2HTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
														 authentication:authentication
																  error:error];
	return [PA2AuthorizationHttpHeader authorizationHeaderWithValue:signature.authHeaderValue];
}

- (NSString*) offlineSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
										   uriId:(NSString*)uriId
											body:(NSData*)body
										   nonce:(NSString*)nonce
										   error:(NSError**)error
{
	if (!nonce) {
		if (error) *error = PA2MakeError(PA2ErrorCodeWrongParameter, @"Nonce parameter is missing.");
		return nil;
	}
	
	if (self.hasPendingProtocolUpgrade) {
		if (error) *error = PA2MakeError(PA2ErrorCodePendingProtocolUpgrade, @"Offline data signing is temporarily unavailable, due to pending protocol upgrade.");
		return nil;
	}
	
	PA2HTTPRequestData * requestData = [[PA2HTTPRequestData alloc] init];
	requestData.body = body;
	requestData.method = @"POST";
	requestData.uri = uriId;
	requestData.offlineNonce = nonce;
	PA2HTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
														 authentication:authentication
																  error:error];
	if (signature) {
		return signature.signature;
	}
	return nil;
}


/**
 This private method implements both online & offline signature calculations. Unlike the public interfaces, method accepts
 PA2HTTPRequestData object as a source for data for signing and returns structured PA2HTTPRequestDataSignature object.
 */
- (PA2HTTPRequestDataSignature*) signHttpRequestData:(PA2HTTPRequestData*)requestData
									  authentication:(PowerAuthAuthentication*)authentication
											   error:(NSError**)error
{
	[self checkForValidSetup];
	
	// Check if there is an activation present
	if (!_session.hasValidActivation) {
		if (error) {
			*error = PA2MakeError(PA2ErrorCodeMissingActivation, nil);
		}
		return nil;
	}
	
	// Determine authentication factor type
	PA2SignatureFactor factor = [self determineSignatureFactorForAuthentication:authentication];
	if (factor == 0) {
		if (error) {
			*error = PA2MakeError(PA2ErrorCodeWrongParameter, nil);
		}
		return nil;
	}
	
	// Generate signature key encryption keys
	BOOL userCancelled = NO;
	PA2SignatureUnlockKeys *keys = [self signatureKeysForAuthentication:authentication userCancelled:&userCancelled];
	if (keys == nil) { // Unable to fetch Touch ID related record - maybe user or iOS canacelled the operation?
		if (error) {
			*error = PA2MakeError(PA2ErrorCodeBiometryCancel, nil);
		}
		return nil;
	}
	
	// Compute signature for provided values and return result.
	PA2HTTPRequestDataSignature * signature = [_session signHttpRequestData:requestData keys:keys factor:factor];
	
	// Update keychain values after each successful calculations
	[self saveSessionState];
	
	if (signature == nil && error) {
		*error = PA2MakeError(PA2ErrorCodeSignatureError, nil);
	}
	return signature;
}


- (BOOL) verifyServerSignedData:(nonnull NSData*)data
					  signature:(nonnull NSString*)signature
					  masterKey:(BOOL)masterKey
{
	[self checkForValidSetup];
	
	PA2SignedData * signedData = [[PA2SignedData alloc] init];
	signedData.signingDataKey = masterKey ? PA2SigningDataKey_ECDSA_MasterServerKey : PA2SigningDataKey_ECDSA_PersonalizedKey;
	signedData.data = data;
	signedData.signatureBase64 = signature;

	return [_session verifyServerSignedData: signedData];
}


#pragma mark - Password

- (BOOL) unsafeChangePasswordFrom:(NSString*)oldPassword
							   to:(NSString*)newPassword
{
	BOOL result = [_session changeUserPassword:[PA2Password passwordWithString:oldPassword]
								   newPassword:[PA2Password passwordWithString:newPassword]];
	if (result) {
		[self saveSessionState];
	}
	return result;
}

- (id<PA2OperationTask>) changePasswordFrom:(NSString*)oldPassword
										 to:(NSString*)newPassword
								   callback:(void(^)(NSError *error))callback
{
	return [self validatePasswordCorrect:oldPassword callback:^(NSError * _Nullable error) {
		if (!error) {
			// Let's change the password
			BOOL result = [_session changeUserPassword:[PA2Password passwordWithString:oldPassword]
										   newPassword:[PA2Password passwordWithString:newPassword]];
			if (result) {
				[self saveSessionState];
			} else {
				error = PA2MakeError(PA2ErrorCodeInvalidActivationState, nil);
			}
		}
		// Call back to application
		callback(error);
	}];
}

- (id<PA2OperationTask>) validatePasswordCorrect:(NSString*)password callback:(void(^)(NSError * error))callback
{
	[self checkForValidSetup];
	return [_client postObject:nil
							to:[PA2RestApiEndpoint validateSignature]
						  auth:[PowerAuthAuthentication possessionWithPassword:password]
					completion:^(PA2RestResponseStatus status, id<PA2Decodable> response, NSError *error) {
						callback(error);
					}];
}

#pragma mark - Biometry

- (id<PA2OperationTask>) addBiometryFactor:(NSString*)password
								  callback:(void(^)(NSError *error))callback
{
	// Check if biometry can be used
	if (![PA2Keychain canUseBiometricAuthentication]) {
		callback(PA2MakeError(PA2ErrorCodeBiometryNotAvailable, nil));
		return nil;
	}
	PowerAuthAuthentication * authentication = [PowerAuthAuthentication possessionWithPassword:password];
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_ADD_BIOMETRY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		if (!error) {
			// Let's add the biometry key
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			keys.biometryUnlockKey = [PA2Session generateSignatureUnlockKey];

			BOOL result = [_session addBiometryFactor:encryptedEncryptionKey
												 keys:keys];
			if (result) {
				// Update keychain values after each successful calculations
				[self saveSessionState];
				[_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
				[_biometryOnlyKeychain addValue:keys.biometryUnlockKey forKey:_biometryKeyIdentifier useBiometry:YES];
			} else {
				error = PA2MakeError(PA2ErrorCodeInvalidActivationState, nil);
			}
		}
		// Call back to application
		callback(error);
	}];
}

- (BOOL) hasBiometryFactor
{
	[self checkForValidSetup];
	BOOL hasValue = [_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier];
	hasValue = hasValue && [_session hasBiometryFactor];
	return hasValue;
}

- (BOOL) removeBiometryFactor
{
	[self checkForValidSetup];
	BOOL result = [_session removeBiometryFactor];
	if (result) {
		// Update keychain values after each successful calculations
		[self saveSessionState];
		[_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
	}
	return result;
}

- (void) unlockBiometryKeysWithPrompt:(NSString*)prompt
                            withBlock:(void(^)(NSDictionary<NSString*, NSData*> *keys, bool userCanceled))block
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status;
        bool userCanceled;
        NSDictionary *keys = [_biometryOnlyKeychain allItemsWithPrompt:prompt withStatus:&status];
        userCanceled = status == errSecUserCanceled;
        block(keys, userCanceled);
    });
}

#pragma mark - Secure vault support


- (id<PA2OperationTask>) fetchEncryptionKey:(PowerAuthAuthentication*)authentication
									  index:(UInt64)index
								   callback:(void(^)(NSData *encryptionKey, NSError *error))callback
{
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_FETCH_ENCRYPTION_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		NSData * encryptionKey = nil;
		if (!error) {
			// Let's unlock encryption key
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			encryptionKey = [_session deriveCryptographicKeyFromVaultKey:encryptedEncryptionKey
																	keys:keys
																keyIndex:index];
			if (!encryptionKey) {
				error = PA2MakeError(PA2ErrorCodeEncryption, nil);
			}
		}
		// Call back to application
		callback(encryptionKey, error);
	}];
}

#pragma mark - Asymmetric signatures

- (id<PA2OperationTask>) signDataWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
												 data:(NSData*)data
											 callback:(void(^)(NSData *signature, NSError *error))callback
{
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_SIGN_WITH_DEVICE_PRIVATE_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		NSData *signature = nil;
		if (!error) {
			// Let's sign the data
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			signature = [_session signDataWithDevicePrivateKey:encryptedEncryptionKey
														  keys:keys
														  data:data];
			// Propagate error
			if (!signature) {
				error = PA2MakeError(PA2ErrorCodeEncryption, nil);
			}
		}
		// Call back to application
		callback(signature, error);
	}];
}

@end

#pragma mark - End-2-End Encryption

@implementation PowerAuthSDK (E2EE)

- (PA2ECIESEncryptor*) eciesEncryptorForApplicationScope
{
	PA2PrivateEncryptorFactory * factory = [[PA2PrivateEncryptorFactory alloc] initWithSession:_session deviceRelatedKey:nil];
	return [factory encryptorWithId:PA2EncryptorId_GenericApplicationScope];
}

- (PA2ECIESEncryptor*) eciesEncryptorForActivationScope
{
	if (![self hasValidActivation]) {
		PA2Log(@"eciesEncryptorForActivation: There's no activation.");
		return nil;
	}
	NSData * deviceKey = [self deviceRelatedKey];
	PA2PrivateEncryptorFactory * factory = [[PA2PrivateEncryptorFactory alloc] initWithSession:_session deviceRelatedKey:deviceKey];
	return [factory encryptorWithId:PA2EncryptorId_GenericActivationScope];
}

@end


#pragma mark - Request synchronization

@implementation PowerAuthSDK (RequestSync)

- (nullable id<PA2OperationTask>) executeBlockOnSerialQueue:(void(^ _Nonnull)(id<PA2OperationTask> _Nonnull task))execute
{
	PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
	operation.executionBlock = ^id(PA2AsyncOperation *op) {
		execute(op);
		return nil;
	};
	return [self executeOperationOnSerialQueue:operation] ? operation : nil;
}

- (BOOL) executeOperationOnSerialQueue:(nonnull NSOperation *)operation
{
	if (![self hasValidActivation]) {
		PA2Log(@"executeOperationOnSerialQueue: There's no activation.");
		return NO;
	}
	[_client.serialQueue addOperation:operation];
	return YES;
}

@end



#pragma mark - Recovery codes

@implementation PowerAuthSDK (RecoveryCode)

- (BOOL) hasActivationRecoveryData
{
	return _session.hasActivationRecoveryData;
}

- (nullable id<PA2OperationTask>) activationRecoveryData:(nonnull PowerAuthAuthentication*)authentication
												callback:(nonnull void(^)(PA2ActivationRecoveryData * _Nullable recoveryData, NSError * _Nullable error))callback
{
	if (!_session.hasActivationRecoveryData) {
		callback(nil, PA2MakeError(PA2ErrorCodeInvalidActivationState, @"Session has no recovery data available."));
		return nil;
	}
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_RECOVERY_CODE callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		PA2ActivationRecoveryData * activationRecovery = nil;
		if (!error) {
			// Let's sign the data
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			PA2RecoveryData * recoveryData = [_session activationRecoveryData:encryptedEncryptionKey keys:keys];
			// Propagate error
			if (recoveryData) {
				activationRecovery = [[PA2ActivationRecoveryData alloc] initWithRecoveryData:recoveryData];
			} else {
				error = PA2MakeError(PA2ErrorCodeEncryption, nil);
			}
		}
		// Call back to application
		callback(activationRecovery, error);
	}];
}

- (nullable id<PA2OperationTask>) confirmRecoveryCode:(nonnull NSString*)recoveryCode
									   authentication:(nonnull PowerAuthAuthentication*)authentication
											 callback:(nonnull void(^)(BOOL alreadyConfirmed, NSError * _Nullable error))callback
{
	[self checkForValidSetup];
	
	// Check if there is an activation present
	if (!_session.hasValidActivation) {
		callback(NO, PA2MakeError(PA2ErrorCodeMissingActivation, nil));
		return nil;
	}
	
	// Validate recovery code
	PA2Otp * otp = [PA2OtpUtil parseFromRecoveryCode:recoveryCode];
	if (!otp) {
		callback(NO, PA2MakeError(PA2ErrorCodeWrongParameter, @"Invalid recovery code."));
		return nil;
	}
	
	// Construct and post request
	PA2ConfirmRecoveryCodeRequest * request = [[PA2ConfirmRecoveryCodeRequest alloc] init];
	request.recoveryCode = otp.activationCode;
	return [_client postObject:request
							to:[PA2RestApiEndpoint confirmRecoveryCode]
						  auth:authentication
					completion:^(PA2RestResponseStatus status, id<PA2Decodable> response, NSError *error) {
						BOOL alreadyConfirmed;
						if (status == PA2RestResponseStatus_OK) {
							alreadyConfirmed = ((PA2ConfirmRecoveryCodeResponse*)response).alreadyConfirmed;
						} else {
							alreadyConfirmed = NO;
						}
						callback(alreadyConfirmed, error);
					}];
}


@end
