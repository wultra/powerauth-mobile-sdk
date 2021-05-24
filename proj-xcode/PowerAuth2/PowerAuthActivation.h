/*
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

#import <PowerAuth2/PowerAuthActivationCode.h>

/**
 The `PowerAuthActivation` object contains activation data required for the activation creation. The object supports
 all types of activation currently supported in the SDK.
 */
@interface PowerAuthActivation : NSObject<NSCopying>

/**
 Use class factory methods to init object.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Create an instance of `PowerAuthActivation` configured with the activation code. The activation code may contain
 an optional signature part, in case that it is scanned from QR code.
 
 The activation's `name` parameter is optional, but recommended to set. You can use the value obtained from
 `UIDevice.current.name` or let the user set the name. The name of activation will be associated with
 an activation record on PowerAuth Server.
 
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param name Activation name to be used for the activation.
 @param error Error reference in case some error occurs.
 @return New instance of `PowerAuthActivation` or `nil` in case that activation code is invalid.
 */
+ (nullable instancetype) activationWithActivationCode:(nonnull NSString*)activationCode
												  name:(nullable NSString*)name
												 error:(NSError * _Nullable * _Nullable)error;

/**
 Creates an instance of `PowerAuthActivation` with an identity attributes for the custom activation purposes.
 
 The activation's `name` parameter is optional, but recommended to set. You can use the value obtained from
 `UIDevice.current.name` or let the user set the name. The name of activation will be associated with
 an activation record on PowerAuth Server.
 
 @param identityAttributes Custom activation parameters that are used to prove identity of a user.
 @param name Activation name to be used for the activation.
 @param error Error reference in case some error occurs.
 @return New instance of `PowerAuthActivation` or `nil` in case that identity attributes are empty.
 */
+ (nullable instancetype) activationWithIdentityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
													  name:(nullable NSString*)name
													 error:(NSError * _Nullable * _Nullable)error;

/**
 Creates an instance of `PowerAuthActivation` with a recovery activation code and PUK.
 
 The activation's `name` parameter is optional, but recommended to set. You can use the value obtained from
 `UIDevice.current.name` or let the user set the name. The name of activation will be associated with
 an activation record on PowerAuth Server.
 
 @param recoveryCode Recovery code, obtained either via QR code scanning or by manual entry.
 @param recoveryPuk PUK obtained by manual entry.
 @param name Activation name to be used for the activation.
 @param error Error reference in case some error occurs.
 @return New instance of `PowerAuthActivation` or `nil` in case that recovery code, or recovery PUK is invalid.
 */
+ (nullable instancetype) activationWithRecoveryCode:(nonnull NSString*)recoveryCode
										 recoveryPuk:(nonnull NSString*)recoveryPuk
												name:(nullable NSString*)name
											   error:(NSError * _Nullable * _Nullable)error;


#pragma mark - Activation customization

/**
 Sets extra attributes of the activation, used for application specific purposes (for example, info about the client
 device or system). This extras string will be associated with the activation record on PowerAuth Server.

 @param extras Extra attributes string.
 @return The same object instance.
 */
- (nonnull instancetype) withExtras:(nonnull NSString*)extras
						 NS_SWIFT_NAME(with(extras:));

/**
 Sets custom attributes dictionary that are processed on Intermediate Server Application.
 Note that this custom data will not be associated with the activation record on PowerAuth Server.

 @param customAttributes Custom attributes. The provided dictionary must contain only objects that can be serialized by `NSJSONSerialization`.
 @return The same object instance.
 */
- (nonnull instancetype) withCustomAttributes:(nonnull NSDictionary<NSString*, id>*)customAttributes
						 NS_SWIFT_NAME(with(customAttributes:));

/**
 Sets an additional activation OTP that can be used only with a regular activation, by activation code.
 
 @param additionalActivationOtp Additional activation OTP.
 @return The same object instance.
 */
- (nonnull instancetype) withAdditionalActivationOtp:(nonnull NSString*)additionalActivationOtp
						 NS_SWIFT_NAME(with(additionalActivationOtp:));


#pragma mark - Properties
/**
 Contains identity attributes, that depends on the type of the activation.
 */
@property (nonatomic, strong, nonnull, readonly) NSDictionary<NSString*,NSString*> * identityAttributes;

/**
 Contains type of the activation (e.g. "CODE", "CUSTOM" or "RECOVERY").
 */
@property (nonatomic, strong, nonnull, readonly) NSString * activationType;

/**
 Contains parsed activation code in case this is a regular activation.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthActivationCode * activationCode;

/**
 Contains activation name in case that the it was set before.
 */
@property (nonatomic, strong, nullable, readonly) NSString * name;

/**
 Contains extra attributes string in case that value was set before.
 */
@property (nonatomic, strong, nullable, readonly) NSString * extras;

/**
 Contains custom attributes dictionary in case that the value was set before.
 */
@property (nonatomic, strong, nullable, readonly) NSDictionary<NSString*, id> * customAttributes;

/**
 Contains additional activation OTP in case taht the value was set before.
 */
@property (nonatomic, strong, nullable, readonly) NSString * additionalActivationOtp;


#pragma mark - Validation

/**
 Validates activation data.
 
 @return `YES` in case that object contains valid activation data.
 */
- (BOOL) validate;

/**
 Validates activation data and returns error if data is not valid.
 
 @return `NSError` in case that object contains invalid activation data.
 */
- (nullable NSError*) validateAndGetError;

@end

