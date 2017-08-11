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

#import "PowerAuthTestServerModel.h"
#import "PowerAuthTestServerConfig.h"

/**
 The PowerAuthTestServerAPI class implements simple SOAP client for communication with
 PowerAuth Java Server. This interface allows a direct manipulation with PowerAuth
 Server entities, like registered applications or user's activations. We're using
 this class only for integration testing purposes, where the PowerAuthSDK
 
 The test server must be configured with disabled application security.
 
 WARNING
 
 This class is available and compiled only for testing purposes. The final, production
 PowerAuth SDK doesn't contain this object.
 */
@interface PowerAuthTestServerAPI : NSObject

/**
 Initializes a test server API object for given |testServerConfig|.
 */
- (id) initWithConfiguration:(PowerAuthTestServerConfig*)testServerConfig;

/**
 Validates connection to the server. The method simply checks whether the test
 server contains required application and application version. If server doesn't
 have these entities, then creates a new ones.
 
 The method also updates a several read only objects, accessible from this class.
 */
- (BOOL) validateConnection;

/**
 Returns YES if object has valid connection.
 */
@property (nonatomic, assign, readonly) BOOL hasValidConnection;

#pragma mark - System

- (PATSSystemStatus*) getSystemStatus;


#pragma mark - SOAP Applications

/**
 Returns list of applications
 */
- (NSArray<PATSApplication*>*) getApplicationList;
/**
 Returns detail of application with required |applicationId|
 */
- (PATSApplicationDetail*) getApplicationDetail:(NSString*)applicationId;
/**
 Creates a new application with required |applicationName| and returns application object.
 */
- (PATSApplication*) createApplication:(NSString*)applicationName;


#pragma mark - SOAP Application Versions

/**
 Creates a new application version for application with |applicationId| with name |versionName|.
 Returns application version object.
 */
- (PATSApplicationVersion*) createApplicationVersion:(NSString*)applicationId versionName:(NSString*)versionName;

/**
 Creates a new application version for application with |applicationId| with name |versionName| if exact the same
 application doesn't exist. The existing version must be supported.
 Returns application version object. The API object must contain a valid connection.
 */
- (PATSApplicationVersion*) createApplicationVersionIfDoesntExist:(NSString*)versionName;

/**
 Changes application version's status to "supported". Returns YES is request succeeded.
 */
- (BOOL) supportApplicationVersion:(NSString*)applicationVersionId;

/**
 Changes application version's status to "unsupported". Returns YES is request succeeded.
 */
- (BOOL) unsupportApplicationVersion:(NSString*)applicationVersionId;


#pragma mark - SOAP Activation

/**
 Initializes an activation for required user. The API object must contain a valid connection.
 */
- (PATSInitActivationResponse*) initializeActivation:(NSString*)userId;

/**
 Returns status of the activation.
 */
- (PATSActivationStatus*) getActivationStatus:(NSString*)activationId;

/**
 Blocks activation and returns simple status after the operation. You can check whether
 the activation was blocked from the returned object.
 */
- (PATSSimpleActivationStatus*) blockActivation:(NSString*)activationId;

/**
 Unblocks activation and returns simple status after the operation. You can check whether
 the activation was unblocked from the returned object.
 */
- (PATSSimpleActivationStatus*) unblockActivation:(NSString*)activationId;

/**
 Commits initialized & prepared activation and returns simple status after the operation.
 Returns YES if commit succeeded.
 */
- (BOOL) commitActivation:(NSString*)activationId;

/**
 Removes an existing activation. Returns YES if activation was successfully removed. 
 Note that you can still check status of removed activation.
 */
- (BOOL) removeActivation:(NSString*)activationId;


#pragma mark - SOAP Signatures

/**
 Request for PA2 signature calculation.
 Returns result object created from SOAP response or nil in case of failure.
 */
- (PATSVerifySignatureResponse*) verifySignature:(NSString*)activationId
											data:(NSString*)normalizedData
									   signature:(NSString*)signature
								   signatureType:(NSString*)signatureType;

/**
 Returns normalized data from given parameters.
 */
- (NSString*) normalizeDataForSignatureWithMethod:(NSString*)httpMethod
											uriId:(NSString*)uriId
											nonce:(NSString*)nonceB64
											 data:(NSData*)data;
/**
 Request for the asymmetric signature (ECDSA) validation procedure.
 */
- (BOOL) verifyECDSASignature:(NSString*)activationId data:(NSData*)data signature:(NSData*)signature;


#pragma mark - Read-only getters

/**
 Contains name of application assigned during the object initialization.
 */
@property (nonatomic, readonly, strong) NSString * applicationNameString;
/**
 Contains name of version assigned during the object initialization.
 */
@property (nonatomic, readonly, strong) NSString * applicationVersionString;
/**
 Contains application detail object. You have to call `validateConnection` method
 to update this property.
 */
@property (nonatomic, readonly, strong) PATSApplicationDetail  * appDetail;
/**
 Contains application version object, You have to call `validateConnection` method 
 to update this property.
 */
@property (nonatomic, readonly, strong) PATSApplicationVersion * appVersion;

@end
