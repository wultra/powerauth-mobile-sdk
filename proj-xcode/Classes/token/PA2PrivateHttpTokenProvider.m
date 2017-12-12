/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2PrivateHttpTokenProvider.h"
#import "PowerAuthSDK.h"
#import "PA2ECIESEncryptor.h"
#import "PA2Client.h"
#import "PA2EncryptedRequest.h"
#import "PA2EncryptedResponse.h"
#import "PA2GetTokenResponse.h"
#import "PA2PrivateMacros.h"

@implementation PA2PrivateHttpTokenProvider
{
	/// Weak reference to parent SDK.
	__weak PowerAuthSDK * _sdk;
	
	/// Weakly
	/// An ECIES encryptor, created from master server public key.
	PA2ECIESEncryptor * 		_encryptor;
	/// A HTTP client for communication with the server
	PA2Client * 				_client;
}

- (id) initWithSdk:(PowerAuthSDK*)sdk
{
	self = [super init];
	if (self) {
		_sdk = sdk;
	}
	return self;
}

- (void) prepareInstanceForConfiguration:(PowerAuthConfiguration*)configuration
{
	// Prepare encryptor
	NSData * pubKeyData = [[NSData alloc] initWithBase64EncodedString:configuration.masterServerPublicKey options:0];
	_encryptor = [[PA2ECIESEncryptor alloc] initWithPublicKey:pubKeyData sharedInfo2:nil];
	// Prepare client
	_client = [[PA2Client alloc] init];
	_client.baseEndpointUrl = configuration.baseEndpointUrl;
	_client.defaultRequestTimeout = [PA2ClientConfiguration sharedInstance].defaultRequestTimeout;
	_client.sslValidationStrategy = [PA2ClientConfiguration sharedInstance].sslValidationStrategy;
}

- (PowerAuthTokenStoreTask) requestTokenWithName:(NSString *)name
								  authentication:(PowerAuthAuthentication *)authentication
									  completion:(void (^)(PA2PrivateTokenData * _Nullable, NSError * _Nullable))completion
{
	PowerAuthSDK * strongSdk = _sdk;
	if (!strongSdk) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
		return nil;
	}
	
	// Prepare request. We're encrypting empty data, so the ephemeral key is only payload in the JSON.
	PA2EncryptedRequest * requestObject = [[PA2EncryptedRequest alloc] init];
	__block PA2ECIESEncryptor * responseDecryptor = nil;
	BOOL success = [_encryptor encryptRequest:nil completion:^(PA2ECIESCryptogram * cryptogram, PA2ECIESEncryptor * decryptor) {
		requestObject.ephemeralPublicKey = cryptogram.keyBase64;
		responseDecryptor = decryptor;
	}];
	if (!success) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil]);
		return nil;
	}
	
	// Prepare operation task...
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	
	// Prepare callback to main thread
	void (^safeCompletion)(PA2PrivateTokenData*, NSError*) = ^(PA2PrivateTokenData * tokenData, NSError * error) {
		dispatch_async(dispatch_get_main_queue(), ^{
			completion(tokenData, error);
		});
	};
	
	// ...and do the rest on background thread, due to expected biometric signature.
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		
		NSError * error = nil;
		// This is tricky. We need to embed that request object before the signature is calculated.
		// We need to use the same function as is used in the PA2Client for data preparation.
		NSData * jsonData = [_client embedNetworkObjectIntoRequest:requestObject];
		if (!jsonData || error) {
			safeCompletion(nil, error);
		}
		// Now sign encrypted data
		PA2AuthorizationHttpHeader * header = [strongSdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/pa/token/create" body:jsonData error:&error];
		if (!header || error) {
			safeCompletion(nil, error);
		}
		task.dataTask = [_client createToken:header encryptedData:requestObject callback:^(PA2RestResponseStatus status, PA2EncryptedResponse * encryptedResponse, NSError * error) {
			PA2PrivateTokenData * tokenData = nil;
			if ((status == PA2RestResponseStatus_OK) && (error == nil)) {
				// Decrypt response
				PA2ECIESCryptogram * responseCryptogram = [[PA2ECIESCryptogram alloc] init];
				responseCryptogram.bodyBase64 = encryptedResponse.encryptedData;
				responseCryptogram.macBase64 = encryptedResponse.mac;
				NSData * responseData = [responseDecryptor decryptResponse:responseCryptogram];
				if (responseData) {
					// Parse JSON
					NSDictionary * responseDictionary = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:responseData options:0 error:&error], NSDictionary);
					if (responseDictionary && !error) {
						// ...and finally, create a private token data object
						PA2GetTokenResponse * responseObject = [[PA2GetTokenResponse alloc] initWithDictionary:responseDictionary];
						tokenData = [[PA2PrivateTokenData alloc] init];
						tokenData.identifier = responseObject.tokenId;
						tokenData.name = name;
						tokenData.secret = responseObject.tokenSecret ? [[NSData alloc] initWithBase64EncodedString:responseObject.tokenSecret options:0] : nil;
						if (!tokenData.hasValidData) {
							// Throw away that object...
							tokenData = nil;
						}
					}
				}
			}
			// call back to the application...
			if (!tokenData && !error) {
				// Create fallback error in case that token has not been created.
				error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil];
			}
			safeCompletion(tokenData, error);
		}];
	});
	return task;
}

- (nullable PowerAuthTokenStoreTask) removeTokenData:(nonnull PA2PrivateTokenData*)tokenData
										  completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion
{
	PowerAuthSDK * strongSdk = _sdk;
	if (!strongSdk) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
		return nil;
	}
	
	// Prepare data for HTTP request
	PA2RemoveTokenRequest * removeRequest = [[PA2RemoveTokenRequest alloc] init];
	removeRequest.tokenId = tokenData.identifier;
	NSData * jsonData = [_client embedNetworkObjectIntoRequest:removeRequest];
	// Sign http request
	NSError * error = nil;
	PowerAuthAuthentication * authentication = [[PowerAuthAuthentication alloc] init];
	authentication.usePossession = YES;
	PA2AuthorizationHttpHeader * signatureHeader = [strongSdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/pa/token/remove" body:jsonData error:&error];
	if (!signatureHeader || error) {
		completion(NO, error);
		return nil;
	}
	
	// Start http request...
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	task.dataTask = [_client removeToken:removeRequest signatureHeader:signatureHeader callback:^(PA2RestResponseStatus status, NSError * _Nullable error) {
		BOOL removed = (status == PA2RestResponseStatus_OK) && (error == nil);
		dispatch_async(dispatch_get_main_queue(), ^{
			completion(removed, error);
		});
	}];
	return task;
}

- (void) cancelTask:(PowerAuthTokenStoreTask)task
{
	if ([task isKindOfClass:[PA2OperationTask class]]) {
		[(PA2OperationTask*)task cancel];
	}
}

@end
