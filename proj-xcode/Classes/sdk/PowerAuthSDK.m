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

#import "PowerAuthSDK.h"

#import "PA2Keychain.h"
#import "PA2OtpUtil.h"

#import "PA2PrivateNetworking.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateHttpTokenProvider.h"
#import "PA2PrivateMacros.h"
#import "PA2WCSessionManager+Private.h"
#import <UIKit/UIKit.h>

#pragma mark - Constants

/** In case a config is missing, exception with this identifier is thrown. */
NSString *const PA2ExceptionMissingConfig		= @"PA2ExceptionMissingConfig";

#pragma mark - PowerAuth SDK implementation

@implementation PowerAuthSDK {
	PowerAuthConfiguration * _configuration;
	PA2KeychainConfiguration * _keychainConfiguration;
	PA2ClientConfiguration * _clientConfiguration;
	
	PA2Client *_client;
	NSString *_biometryKeyIdentifier;
	PA2Keychain *_statusKeychain;
	PA2Keychain *_sharedKeychain;
	PA2Keychain *_biometryOnlyKeychain;
	PA2PrivateHttpTokenProvider * _remoteHttpTokenProvider;
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
	_client = [[PA2Client alloc] init];
	_client.baseEndpointUrl = _configuration.baseEndpointUrl;
	_client.defaultRequestTimeout = _clientConfiguration.defaultRequestTimeout;
	_client.sslValidationStrategy = _clientConfiguration.sslValidationStrategy;
	
	// Create a new keychain instances
	_statusKeychain			= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Status
													accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_sharedKeychain			= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Possession
													accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_biometryOnlyKeychain	= [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Biometry];
	// Initialize token store with its own keychain as a backing storage and remote token provider.
	PA2Keychain * tokenStoreKeychain = [[PA2Keychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_TokenStore
																   accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
	_remoteHttpTokenProvider = [[PA2PrivateHttpTokenProvider alloc] initWithSdk:self];
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
	
	// Initialize encryptor factory
	_encryptorFactory = [[PA2EncryptorFactory alloc] initWithSession:_session];
	
	
	// Attempt to restore session state
	[self restoreState];
	
	// Register this instance to handle messages
	// NOTE: The actual PA2WCSessionDataHandler implementation is in +WatchSupportPrivate category,
	//       so we can freely cast self to this protocol.
	[[PA2WCSessionManager sharedInstance] registerDataHandler:(id<PA2WCSessionDataHandler>)self];
}

- (void) dealloc
{
	// Unregister this instance for processing packets...
	// NOTE: The actual PA2WCSessionDataHandler implementation is in +WatchSupportPrivate category,
	//       so we can freely cast self to this protocol.
	[[PA2WCSessionManager sharedInstance] unregisterDataHandler:(id<PA2WCSessionDataHandler>)self];
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
- (void) checkForValidSetup {
	// Check for the session setup
	if (!_session.hasValidSetup) {
		[PowerAuthSDK throwInvalidConfigurationException];
	}
}

- (PA2ActivationStep1Param*) paramStep1WithActivationCode:(NSString*)activationCode {
	
	PA2Otp *otp = [PA2OtpUtil parseFromActivationCode:activationCode];
	if (otp == nil) {
		return nil;
	}
	
	// Prepare result and return
	PA2ActivationStep1Param *result = [[PA2ActivationStep1Param alloc] init];
	result.activationIdShort = otp.activationIdShort;
	result.activationOtp = otp.activationOtp;
	result.activationSignature = otp.activationSignature;
	
	return result;
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
											 userCancelled:(nullable BOOL *)userCancelled {
	
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
					PA2Log(@"ERROR! You are attempting Touch ID authentication despite the fact related key value is not present in the Keychain. We have generated an ad-hoc random key and your authentication will fail. Use PowerAuthSDK:hasBiometryFactor method to check the status of this key and disable Touch ID if the method returns NO / false value.");
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
												 withVaultUnlock:(BOOL)vaultUnlock
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
	if (factor > 0 && vaultUnlock) {
		factor |= PA2SignatureFactor_PrepareForVaultUnlock;
	}
	return factor;
}

- (PA2OperationTask*) fetchEncryptedVaultUnlockKey:(PowerAuthAuthentication*)authentication
											reason:(PA2VaultUnlockReason)reason
										 callback:(void(^)(NSString * encryptedEncryptionKey, NSError *error))callback {
	
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	[self checkForValidSetup];
	
	// Check if there is an activation present
	if (!_session.hasValidActivation) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain
											 code:PA2ErrorCodeMissingActivation
										 userInfo:nil];
		callback(nil, error);
		return nil;
	}
	
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		
		// Build request object & request data
		PA2VaultUnlockRequest * request = [[PA2VaultUnlockRequest alloc] initWithReason:reason];
		NSData * requestData = [_client embedNetworkObjectIntoRequest:request];
		
		// Compute authorization header based on constants from the specification.
		NSError *error = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		PA2AuthorizationHttpHeader *httpHeader = [self requestSignatureWithAuthentication:authentication
																			  vaultUnlock:YES
																				   method:@"POST"
																					uriId:@"/pa/vault/unlock"
																					 body:requestData
																					error:&error];
#pragma clang diagnostic pop
		if (error) {
			callback(nil, error);
			return;
		}
		if (task.isCancelled) {
			NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeOperationCancelled userInfo:nil];
			callback(nil, error);
			return;
		}
		
		// Perform the server request
		NSURLSessionDataTask *dataTask = [_client vaultUnlock:httpHeader request:request callback:^(PA2RestResponseStatus status, PA2VaultUnlockResponse *response, NSError *clientError) {
			// Network communication completed correctly
			if (status == PA2RestResponseStatus_OK) {
				callback(response.encryptedVaultEncryptionKey, nil);
			} else { // Network error occurred
				callback(nil, clientError);
			}
		}];
		task.dataTask = dataTask;
	});
	
	return task;
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

- (BOOL) restoreState {
	NSData *sessionData = [_statusKeychain dataForKey:_configuration.instanceId status:nil];
	if (sessionData) {
		[_session resetSession];
		return [_session deserializeState:sessionData];
	} else {
		return NO;
	}
}

- (BOOL) canStartActivation {
	[self checkForValidSetup];
	return _session.canStartActivation;
}

- (BOOL) hasPendingActivation {
	
	[self checkForValidSetup];
	return _session.hasPendingActivation;
}

- (BOOL) hasValidActivation {
	
	[self checkForValidSetup];
	return _session.hasValidActivation;
}

#pragma mark Creating a new activation

- (PA2OperationTask*) createActivationWithName:(NSString*)name
								activationCode:(NSString*)activationCode
									  callback:(void(^)(PA2ActivationResult *result, NSError *error))callback {
	return [self createActivationWithName:name activationCode:activationCode extras:nil callback:callback];
}

- (PA2OperationTask*) createActivationWithName:(NSString*)name
								activationCode:(NSString*)activationCode
										extras:(NSString*)extras
									  callback:(void(^)(PA2ActivationResult *result, NSError *error))callback {
	
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	[self checkForValidSetup];
	
	// Check if activation may be started
	if (![self canStartActivation]) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationState userInfo:nil];
		callback(nil, error);
		return nil;
	}
	
	// Reset session & possible activation data
	[self removeActivationLocal];
		
	// Prepare crypto module request
	PA2ActivationStep1Param *paramStep1 = [self paramStep1WithActivationCode:activationCode];
	
	// Obtain crypto module response
	PA2ActivationStep1Result *resultStep1 = [_session startActivation:paramStep1];
	if (nil == resultStep1) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
		callback(nil, error);
		return nil;
	}
	// After this point, each error must lead to [_session resetSession];
	
	// Perform exchange over PowerAuth 2.0 Standard RESTful API
	PA2CreateActivationRequest *request = [[PA2CreateActivationRequest alloc] init];
	request.activationIdShort = paramStep1.activationIdShort;
	request.activationName = name;
	request.activationNonce = resultStep1.activationNonce;
	request.applicationKey = _configuration.appKey;
	request.applicationSignature = resultStep1.applicationSignature;
	request.encryptedDevicePublicKey = resultStep1.cDevicePublicKey;
	request.ephemeralPublicKey = resultStep1.ephemeralPublicKey;
	request.extras = extras;
	
	NSURLSessionDataTask *dataTask = [_client createActivation:request callback:^(PA2RestResponseStatus status, PA2CreateActivationResponse *response, NSError *clientError) {
		
		NSError * errorToReport = clientError;
		PA2ActivationResult * activationResult = nil;
		if (!errorToReport) {
			// Network communication completed correctly
			if (status == PA2RestResponseStatus_OK) {
				
				// Prepare crypto module request
				PA2ActivationStep2Param *paramStep2 = [[PA2ActivationStep2Param alloc] init];
				paramStep2.activationId = response.activationId;
				paramStep2.ephemeralNonce = response.activationNonce;
				paramStep2.ephemeralPublicKey = response.ephemeralPublicKey;
				paramStep2.encryptedServerPublicKey = response.encryptedServerPublicKey;
				paramStep2.serverDataSignature = response.encryptedServerPublicKeySignature;
				
				// Obtain crypto module response
				PA2ActivationStep2Result *resultStep2 = [_session validateActivationResponse:paramStep2];
				if (resultStep2) {
					// Everything is OK
					activationResult = [[PA2ActivationResult alloc] init];
					activationResult.activationFingerprint = resultStep2.activationFingerprint;
					activationResult.customAttributes = response.customAttributes;
				} else {
					// Encryption error
					errorToReport = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
				}
				
			} else {
				// Activation error occurred
				errorToReport = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
			}
		}
		if (errorToReport) {
			[_session resetSession];
		}
		callback(activationResult, errorToReport);
		
	}];
	task.dataTask = dataTask;
	return task;
}

- (PA2OperationTask*) createActivationWithName:(NSString*)name
							identityAttributes:(NSDictionary<NSString*,NSString*>*)identityAttributes
								  customSecret:(NSString*)customSecret
										extras:(NSString*)extras
							  customAttributes:(NSDictionary<NSString*,NSString*>*)customAttributes
										   url:(NSURL*)url
								   httpHeaders:(NSDictionary*)httpHeaders
									  callback:(void(^)(PA2ActivationResult *result, NSError * error))callback {
	
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	[self checkForValidSetup];
	
	// Check if activation may be started
	if (![self canStartActivation]) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationState userInfo:nil];
		callback(nil, error);
		return nil;
	}
	
	// Reset session & possible activation data
	[self removeActivationLocal];

	// Prepare identity attributes token
	NSData *identityAttributesData = [_session prepareKeyValueDictionaryForDataSigning:identityAttributes];
	NSString *identityAttributesString = [identityAttributesData base64EncodedStringWithOptions:kNilOptions];
	
	// Prepare crypto module request
	PA2ActivationStep1Param *paramStep1 = [[PA2ActivationStep1Param alloc] init];
	paramStep1.activationIdShort = identityAttributesString;
	paramStep1.activationOtp = customSecret;
	paramStep1.activationSignature = nil;
	
	// Obtain crypto module response
	PA2ActivationStep1Result *resultStep1 = [_session startActivation:paramStep1];
	if (nil == resultStep1) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
		callback(nil, error);
		return nil;
	}
	// After this point, each error must lead to [_session resetSession];
	
	// Perform exchange over PowerAuth 2.0 Standard RESTful API
	PA2CreateActivationRequest *powerauth = [[PA2CreateActivationRequest alloc] init];
	powerauth.activationIdShort = paramStep1.activationIdShort;
	powerauth.activationName = name;
	powerauth.activationNonce = resultStep1.activationNonce;
	powerauth.applicationKey = _configuration.appKey;
	powerauth.applicationSignature = resultStep1.applicationSignature;
	powerauth.encryptedDevicePublicKey = resultStep1.cDevicePublicKey;
	powerauth.ephemeralPublicKey = resultStep1.ephemeralPublicKey;
	powerauth.extras = extras;
	
	PA2DirectCreateActivationRequest * request = [[PA2DirectCreateActivationRequest alloc] init];
	request.identity = identityAttributes;
	request.customAttributes = customAttributes;
	request.powerauth = powerauth;
	
	NSData *requestData = [NSJSONSerialization dataWithJSONObject:[request toDictionary]
														  options:kNilOptions
															error:nil];
	
	PA2RequestResponseNonPersonalizedEncryptor *encryptor = [_encryptorFactory buildRequestResponseNonPersonalizedEncryptor];
	
	PA2Request *encryptedRequest = [encryptor encryptRequestData:requestData error:nil];
	NSData *encryptedRequestData = [NSJSONSerialization dataWithJSONObject:[encryptedRequest toDictionary]
																   options:kNilOptions
																	 error:nil];
	
	NSURLSessionDataTask *dataTask = [_client postToUrl:url data:encryptedRequestData headers:httpHeaders completion:^(NSData * httpData, NSURLResponse * response, NSError * clientError) {
		
		NSError * errorToReport = clientError;
		PA2ActivationResult * activationResult = nil;
		if (!errorToReport) {
			NSDictionary *encryptedResponseDictionary;
			if (httpData) {
				encryptedResponseDictionary = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:httpData options:kNilOptions error:nil], NSDictionary);
			} else {
				encryptedResponseDictionary = nil;
			}
			PA2Response *encryptedResponse = [[PA2Response alloc] initWithDictionary:encryptedResponseDictionary
																  responseObjectType:[PA2NonPersonalizedEncryptedObject class]];
			
			// Network communication completed correctly
			if (encryptedResponse.status == PA2RestResponseStatus_OK) {
				
				NSData *decryptedResponseData = [encryptor decryptResponse:encryptedResponse error:nil];
				NSDictionary *createActivationResponseDictionary;
				if (decryptedResponseData) {
					createActivationResponseDictionary = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:decryptedResponseData options:0 error:nil], NSDictionary);
				} else {
					createActivationResponseDictionary = nil;
				}
				
				PA2CreateActivationResponse *responseObject = [[PA2CreateActivationResponse alloc] initWithDictionary:createActivationResponseDictionary];
				
				// Prepare crypto module request
				PA2ActivationStep2Param *paramStep2 = [[PA2ActivationStep2Param alloc] init];
				paramStep2.activationId = responseObject.activationId;
				paramStep2.ephemeralNonce = responseObject.activationNonce;
				paramStep2.ephemeralPublicKey = responseObject.ephemeralPublicKey;
				paramStep2.encryptedServerPublicKey = responseObject.encryptedServerPublicKey;
				paramStep2.serverDataSignature = responseObject.encryptedServerPublicKeySignature;
				
				// Obtain crypto module response
				PA2ActivationStep2Result *resultStep2 = [_session validateActivationResponse:paramStep2];
				if (resultStep2) {
					// Everything is OK
					activationResult = [[PA2ActivationResult alloc] init];
					activationResult.activationFingerprint = resultStep2.activationFingerprint;
					activationResult.customAttributes = responseObject.customAttributes;
				} else {
					// Error occurred
					errorToReport = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
				}
			} else {
				// Activation error occurred, propagate response data to the error object
				// Try to parse response data as JSON
				NSDictionary * responseJsonObject;
				if (httpData){
					responseJsonObject = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:httpData options:kNilOptions error:nil], NSDictionary);
				} else {
					responseJsonObject = nil;
				}
				NSMutableDictionary * additionalInfo = [NSMutableDictionary dictionaryWithCapacity:2];
				if (httpData) {
					additionalInfo[PA2ErrorInfoKey_ResponseData] = httpData;
				}
				if (responseJsonObject) {
					additionalInfo[PA2ErrorInfoKey_AdditionalInfo] = responseJsonObject;
				}
				errorToReport = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:additionalInfo];
			}
		}
		if (errorToReport) {
			[_session resetSession];
		}
		callback(activationResult, errorToReport);
		
	}];
	task.dataTask = dataTask;
	return task;
	
}

- (PA2OperationTask*) createActivationWithName:(NSString*)name
							identityAttributes:(NSDictionary<NSString*,NSString*>*)identityAttributes
										   url:(NSURL*)url
									  callback:(void(^)(PA2ActivationResult *result, NSError * error))callback {
	return [self createActivationWithName:name
					   identityAttributes:identityAttributes
							 customSecret:@"00000-00000" // aka "zero code"
								   extras:nil
						 customAttributes:nil
									  url:url
							  httpHeaders:nil
								 callback:callback];
}

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

#pragma mark Getting activations state

- (PA2OperationTask*) fetchActivationStatusWithCallback:(void(^)(PA2ActivationStatus *status, NSDictionary *customObject, NSError *error))callback {
	
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	[self checkForValidSetup];
	
	// Check if there is an activation present, valid or pending
	if (!_session.hasValidActivation) {
		NSInteger errorCode = _session.hasPendingActivation ? PA2ErrorCodeActivationPending : PA2ErrorCodeMissingActivation;
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:errorCode userInfo:nil];
		callback(nil, nil, error);
		return nil;
	}
	
	// Perform the server request
	PA2ActivationStatusRequest *request = [[PA2ActivationStatusRequest alloc] init];
	request.activationId = _session.activationIdentifier;
	NSURLSessionDataTask *dataTask = [_client getActivationStatus:request callback:^(PA2RestResponseStatus status, PA2ActivationStatusResponse *response, NSError *clientError) {
		
		// Network communication completed correctly
		if (status == PA2RestResponseStatus_OK) {
			
			// Prepare unlocking key (possession factor only)
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			
			// Attempt to decode the activation status
			PA2ActivationStatus *status = [_session decodeActivationStatus:response.encryptedStatusBlob keys:keys];
			
			// Everything was OK
			if (status) {
				_lastFetchedActivationStatus = status;
				_lastFetchedCustomObject = response.customObject;
				callback(status, response.customObject, nil);
			}
			// Error occurred when decoding status
			else {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationData userInfo:nil];
				callback(nil, response.customObject, error);
			}
			
		}
		// Network error occurred
		else {
			callback(nil, nil, clientError);
		}
	}];
	task.dataTask = dataTask;
	return task;
}

#pragma mark Removing an activation

- (PA2OperationTask*) removeActivationWithAuthentication:(PowerAuthAuthentication*)authentication
												callback:(void(^)(NSError *error))callback {
	
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	[self checkForValidSetup];
	
	// Check if there is an activation present
	if (!_session.hasValidActivation) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain
											 code:PA2ErrorCodeMissingActivation
										 userInfo:nil];
		callback(error);
		return nil;
	}
	
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		
		// Compute authorization header based on constants from the specification.
		NSError *error = nil;
		PA2AuthorizationHttpHeader *httpHeader = [self requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/pa/activation/remove" body:nil error:&error];
		if (error) {
			callback(error);
			return;
		}
		
		if (task.isCancelled) {
			NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeOperationCancelled userInfo:nil];
			callback(error);
			return;
		}
		
		// Perform the server request
		NSURLSessionDataTask *dataTask = [_client removeActivation:httpHeader callback:^(PA2RestResponseStatus status, NSError *clientError) {
			// Network communication completed correctly
			if (status == PA2RestResponseStatus_OK) {
				[self removeActivationLocal];
				callback(nil);
			}
			// Network error occurred
			// TODO: Improvement: We can try to fetch status in case of error and handle possible network error silently.
			else {
				callback(clientError);
			}
		}];
		
		task.dataTask = dataTask;
		
	});
	
	return task;
}

- (void) removeActivationLocal {
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
	[_tokenStore removeAllLocalTokens];
	[_session resetSession];
	// Reset activation status
	_lastFetchedActivationStatus = nil;
	_lastFetchedCustomObject = nil;
}


#pragma mark Computing signatures

- (PA2AuthorizationHttpHeader*) requestGetSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
																uriId:(NSString*)uriId
															   params:(NSDictionary<NSString*, NSString*>*)params
																error:(NSError**)error {
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
															 error:(NSError**)error {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	return [self requestSignatureWithAuthentication:authentication
										vaultUnlock:NO
											 method:method
											  uriId:uriId
											   body:body
											  error:error];
#pragma clang diagnostic pop
}

- (PA2AuthorizationHttpHeader*) requestSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
													   vaultUnlock:(BOOL)vaultUnlock
															method:(NSString*)method
															 uriId:(NSString*)uriId
															  body:(NSData*)body
															 error:(NSError**)error
{
	PA2HTTPRequestData * requestData = [[PA2HTTPRequestData alloc] init];
	requestData.body = body;
	requestData.method = method;
	requestData.uri = uriId;
	PA2HTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
														 authentication:authentication
															vaultUnlock:vaultUnlock
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
		return nil;
	}
	
	PA2HTTPRequestData * requestData = [[PA2HTTPRequestData alloc] init];
	requestData.body = body;
	requestData.method = @"POST";
	requestData.uri = uriId;
	requestData.offlineNonce = nonce;
	PA2HTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
														 authentication:authentication
															vaultUnlock:NO
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
										 vaultUnlock:(BOOL)vaultUnlock
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
	PA2SignatureFactor factor = [self determineSignatureFactorForAuthentication:authentication withVaultUnlock:vaultUnlock];
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
	[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
	
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


#pragma mark Activation sign in factor management

- (BOOL) unsafeChangePasswordFrom:(NSString*)oldPassword
							   to:(NSString*)newPassword {
	
	BOOL result = [_session changeUserPassword:[PA2Password passwordWithString:oldPassword]
								   newPassword:[PA2Password passwordWithString:newPassword]];
	if (result) {
		[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
	}
	return result;
}

- (PA2OperationTask*) changePasswordFrom:(NSString*)oldPassword
									  to:(NSString*)newPassword
								callback:(void(^)(NSError *error))callback {
	
	// Setup a new authentication object
	PowerAuthAuthentication *authentication = [[PowerAuthAuthentication alloc] init];
	authentication.usePossession = YES;
	authentication.usePassword = oldPassword;
	authentication.useBiometry = NO;
	
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_PASSWORD_CHANGE callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		if (!error) {
			// Let's change the password
			BOOL result = [_session changeUserPassword:[PA2Password passwordWithString:oldPassword]
										   newPassword:[PA2Password passwordWithString:newPassword]];
			if (result) {
				[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
				callback(nil);
			} else {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidActivationState userInfo:nil];
				callback(error);
			}
		} else {
			callback(error);
		}
	}];
}

- (PA2OperationTask*) addBiometryFactor:(NSString*)password
							   callback:(void(^)(NSError *error))callback {
	
	// Check if biometry can be used
	if (![PA2Keychain canUseBiometricAuthentication]) {
		NSError *error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeBiometryNotAvailable userInfo:nil];
		callback(error);
		return nil;
	}
	
	// Compute authorization header based on constants from the specification.
	PowerAuthAuthentication *authentication = [[PowerAuthAuthentication alloc] init];
	authentication.usePossession	= YES;
	authentication.useBiometry		= NO;
	authentication.usePassword		= password;
	
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_ADD_BIOMETRY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		if (!error) {
			
			if (encryptedEncryptionKey == nil) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationState
												 userInfo:nil];
				callback(error);
				return;
			}
			
			// Let's add the biometry key
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			keys.biometryUnlockKey = [PA2Session generateSignatureUnlockKey];
			
			BOOL result = [_session addBiometryFactor:encryptedEncryptionKey
												 keys:keys];
			// Propagate error
			if (!result) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationState
												 userInfo:nil];
				callback(error);
			} else {
				// Update keychain values after each successful calculations
				[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
				[_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
				[_biometryOnlyKeychain addValue:keys.biometryUnlockKey forKey:_biometryKeyIdentifier useBiometry:YES];
				callback(nil);
			}
		} else {
			callback(error);
		}
	}];
}

- (BOOL) hasBiometryFactor {
	[self checkForValidSetup];
	BOOL hasValue = [_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier];
	hasValue = hasValue && [_session hasBiometryFactor];
	return hasValue;
}

- (BOOL) removeBiometryFactor {
	[self checkForValidSetup];
	BOOL result = [_session removeBiometryFactor];
	if (result) {
		// Update keychain values after each successful calculations
		[_statusKeychain updateValue:[_session serializedState] forKey:_configuration.instanceId];
		[_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
	}
	return result;
}

- (void) unlockBiometryKeysWithPrompt:(NSString*)prompt
                            withBlock:(void(^)(NSDictionary<NSString*, NSData*> *keys, bool userCanceled))block {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status;
        bool userCanceled;
        NSDictionary *keys = [_biometryOnlyKeychain allItemsWithPrompt:prompt withStatus:&status];
        userCanceled = status == errSecUserCanceled;
        block(keys, userCanceled);
    });
}

#pragma mark Secure vault support


- (PA2OperationTask*) fetchEncryptionKey:(PowerAuthAuthentication*)authentication
								   index:(UInt64)index
								callback:(void(^)(NSData *encryptionKey, NSError *error))callback {
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_FETCH_ENCRYPTION_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		if (!error) {
			
			if (encryptedEncryptionKey == nil) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationState
												 userInfo:nil];
				callback(nil, error);
				return;
			}
			
			// Let's unlock encryption key
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			NSData *key = [_session deriveCryptographicKeyFromVaultKey:encryptedEncryptionKey
																  keys:keys
															  keyIndex:index];
			// Propagate error
			if (key == nil) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationData
												 userInfo:nil];
				callback(nil, error);
			} else {
				callback(key, nil);
			}
		} else {
			callback(nil, error);
		}
	}];
}

#pragma mark Asymmetric signatures

- (PA2OperationTask*) signDataWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
											  data:(NSData*)data
										  callback:(void(^)(NSData *signature, NSError *error))callback {
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_SIGN_WITH_DEVICE_PRIVATE_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		if (!error) {
			
			if (encryptedEncryptionKey == nil) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationState
												 userInfo:nil];
				callback(nil, error);
				return;
			}
			
			// Let's sign the data
			PA2SignatureUnlockKeys *keys = [[PA2SignatureUnlockKeys alloc] init];
			keys.possessionUnlockKey = [self deviceRelatedKey];
			NSData *signature = [_session signDataWithDevicePrivateKey:encryptedEncryptionKey
																  keys:keys
																  data:data];
			// Propagate error
			if (signature == nil) {
				NSError *error = [NSError errorWithDomain:PA2ErrorDomain
													 code:PA2ErrorCodeInvalidActivationData
												 userInfo:nil];
				callback(nil, error);
			} else {
				callback(signature, nil);
			}
		} else {
			callback(nil, error);
		}
	}];
}

- (PA2OperationTask*) validatePasswordCorrect:(NSString*)password callback:(void(^)(NSError * error))callback
{
	PowerAuthAuthentication *authentication = [[PowerAuthAuthentication alloc] init];
	authentication.usePossession = YES;
	authentication.useBiometry = NO;
	authentication.usePassword = password;
	return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_PASSWORD_VALIDATE callback:^(NSString *encryptedEncryptionKey, NSError *error) {
		callback(error);
	}];
}

@end
