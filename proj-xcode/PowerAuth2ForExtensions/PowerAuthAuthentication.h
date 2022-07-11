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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

#if PA2_HAS_LACONTEXT == 1
#import <LocalAuthentication/LocalAuthentication.h>
#endif

/** Class representing a multi-factor authentication object.
 */
@interface PowerAuthAuthentication : NSObject<NSCopying>

/// Indicates if a possession factor should be used.
///
/// Modifying content of usePossession property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, assign) BOOL usePossession;

/// Indicates if a biometry factor should be used.
///
/// Modifying content of useBiometry property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, assign) BOOL useBiometry;

/// Password to be used for knowledge factor, or nil of knowledge factor should not be used.
///
/// Modifying content of usePassword property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, strong, nullable) NSString *usePassword;

/// Specifies the text displayed on Touch or Face ID prompt in case biometry is required to obtain data.
///
/// Use this value to give user a hint on what is biometric authentication used for in this specific authentication.
/// For example, include a name of the account user uses to log in.
///
/// Modifying content of biometryPrompt property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, strong, nullable) NSString *biometryPrompt;

/// Indicates if a biometry factor should be used. If both biometryContext and biometryPrompt properties are set, then the context will be applied.
@property (nonatomic, strong, nullable, readonly) LAContext *biometryContext API_UNAVAILABLE(watchos, tvos);

/// If 'usePossession' is set to YES, this value may specify possession key data. If no custom data is specified, default possession key is used.
///
/// Modifying content of overridenPossessionKey property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, strong, nullable) NSData *overridenPossessionKey;

/// If 'useBiometry' is set to YES, this value may specify biometry key data. If no custom data is specified, default biometry key is used for the PowerAuthSDK instance, based on the keychain configuration and SDK instance configuration.
///
/// Modifying content of overridenBiometryKey property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
@property (nonatomic, strong, nullable) NSData *overridenBiometryKey;


// Make setters deprecated

/// Modifying content of usePossession property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setUsePossession:(BOOL)usePossession PA2_DEPRECATED(1.7.0);
/// Modifying content of usePassword property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setUsePassword:(nullable NSString*)usePassword PA2_DEPRECATED(1.7.0);
/// Modifying content of useBiometry property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setUseBiometry:(BOOL)useBiometry PA2_DEPRECATED(1.7.0);
/// Modifying content of biometryPrompt property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setBiometryPrompt:(nullable NSString*)biometryPrompt PA2_DEPRECATED(1.7.0);
/// Modifying content of overridenPossessionKey property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setOverridenPossessionKey:(nullable NSData*)overridenPossessionKey PA2_DEPRECATED(1.7.0);
/// Modifying content of overridenBiometryKey property is deprecated. Please use appropriate static method to create PowerAuthAuthentication instance.
- (void) setOverridenBiometryKey:(nullable NSData*)overridenBiometryKey PA2_DEPRECATED(1.7.0);

@end

@interface PowerAuthAuthentication (EasyAccessors)

#if PA2_HAS_CORE_MODULE

// Commit, Possession + Knowledge

/// Create a new instance of authentication object configured for activation commit with password.
/// 
/// Function is not available for App extensions and on watchOS.
///
/// @param password Password used for the knowledge factor.
/// @return Instance of authentication object configured for activation commit with password.
+ (nonnull PowerAuthAuthentication*) commitWithPassword:(nonnull NSString*)password
						NS_SWIFT_NAME(commitWithPassword(password:));

/// Create a new instance of authentication object configured for activation commit with password and custom possession key.
///
/// Function is not available for App extensions and on watchOS.
///
/// @param password Password used for the knowledge factor.
/// @param customPossessionKey Custom key used for possession factor.
/// @return Instance of authentication object configured for activation commit with password and custom possession key.
+ (nonnull PowerAuthAuthentication*) commitWithPassword:(nonnull NSString*)password
									customPossessionKey:(nonnull NSData*)customPossessionKey
						NS_SWIFT_NAME(commitWithPassword(password:customPossessionKey:));

// Commit, Possession + Knowledge + Biometry

/// Create a new instance of authentication object configured for activation commit with password and with biometry.
///
/// Function is not available for App extensions and on watchOS.
///
/// @param password Password used for the knowledge factor.
/// @return Instance of authentication object configured for activation commit with password and biometry.
+ (nonnull PowerAuthAuthentication*) commitWithPasswordAndBiometry:(nonnull NSString*)password
						NS_SWIFT_NAME(commitWithPasswordAndBiometry(password:));

/// Create a new instance of authentication object configured for activation commit with password and with biometry.
/// This variant of function allows you to use custom keys for biometry and possession factors.
///
/// Function is not available for App extensions and on watchOS.
///
/// @param password Password used for the knowledge factor.
/// @param customBiometryKey Custom key used for biometry factor.
/// @param customPossessionKey Custom key used for possession factor.
/// @return Instance of authentication object configured for activation commit with password and biometry, allowing to use custom keys for possession and biometry factors.
+ (nonnull PowerAuthAuthentication*) commitWithPasswordAndBiometry:(nonnull NSString*)password
												 customBiometryKey:(nullable NSData*)customBiometryKey
											   customPossessionKey:(nullable NSData*)customPossessionKey
						NS_SWIFT_NAME(commitWithPasswordAndBiometry(password:customBiometryKey:customPossessionKey:));

#endif // PA2_HAS_CORE_MODULE

// Signing, Possession only

/// Create a new instance of authentication object preconfigured for signing with a possession factor.
/// @return Instance of PowerAuthAuthentication configured for signing with a possession factor.
+ (nonnull PowerAuthAuthentication *) possession;

/// Create a new instance of authentication object preconfigured for signing with a possession factor, with using custom possession key.
/// @param customPossessionKey Custom key used for possession factor.
/// @return Instance of PowerAuthAuthentication configured for signing with a possession factor with using custom possession key.
+ (nonnull PowerAuthAuthentication *) possessionWithCustomPossessionKey:(nonnull NSData*)customPossessionKey
						NS_SWIFT_NAME(possession(customPossessionKey:));

// Signing, Possession + Biometry

/// Create a new instance of authentication object preconfigured for signing with a possession and biometry factors.
/// @return Instance of PowerAuthAuthentication configured for signing with a possession and biometry factors.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometry;


/// Returns a new instance of authentication object preconfigured for a combination of possession and biometry factors.
/// @param customBiometryKey Custom key used for biometry factor.
/// @param customPossessionKey Custom key used for possession factor.
/// @return New instance of authentication object configured for signing with a possession and biometry factors, with custom biometry and possession keys.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryWithCustomBiometryKey:(nullable NSData*)customBiometryKey
															  customPossessionKey:(nullable NSData*)customPossessionKey
						NS_SWIFT_NAME(possessionWithBiometry(customBiometryKey:customPossessionKey:));

/// Create a new instance of authentication object preconfigured for signign with combination of possession and biometry factors and with prompt,
/// displayed in the system biometric authentication dialog.
/// @param biometryPrompt Prompt displayed in the system biometric authentication dialog.
/// @return New instance of authentication object configured for signing with a possession and biometry factors, with custom prompt displayed in the system biometric authentication dialog.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryPrompt:(nonnull NSString*)biometryPrompt
						NS_SWIFT_NAME(possessionWithBiometry(prompt:));

/// Create a new instance of authentication object preconfigured for signign with combination of possession and biometry factors and with prompt,
/// displayed in the system biometric authentication dialog. This variant of function allows you also use the custom possession key for the possession factor.
/// @param biometryPrompt Prompt displayed in the system biometric authentication dialog.
/// @return New instance of authentication object configured for signing with a custom possession key and biometry factors, with custom prompt displayed in the system biometric authentication dialog.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryPrompt:(nonnull NSString*)biometryPrompt
											   customPossessionKey:(nonnull NSData*)customPossessionKey
						NS_SWIFT_NAME(possessionWithBiometry(prompt:customPossessionKey:));

/// Create a new instance of authentication object preconfigured for signing with combination of possession and biometry factors and with local
/// authentication context. The context allows you to better customize the system biometric authentication dialog.
/// @param context LAContext for the system biometric authentication dialog.
/// @return New instance of authentication object configured for signing with a possession and biometry factors, with local authentication context.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryContext:(nonnull LAContext*)context
						NS_SWIFT_NAME(possessionWithBiometry(context:))
						API_UNAVAILABLE(watchos, tvos);

/// Create a new instance of authentication object preconfigured for signing with combination of possession and biometry factors and with local
/// authentication context. The context allows you to better customize the system biometric authentication dialog. This variant of function allows
/// you also use the custom possession key for the possession factor.
/// @param context LAContext for the system biometric authentication dialog.
/// @return New instance of authentication object configured for signing with a custom possession key and biometry factor, with local authentication context.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryContext:(nonnull LAContext*)context
												customPossessionKey:(nonnull NSData*)customPossessionKey
						NS_SWIFT_NAME(possessionWithBiometry(context:customPossessionKey:))
						API_UNAVAILABLE(watchos, tvos);


// Signing, Possession + Knowledge

/// Create a new instance of authentication object preconfigured for combination of possesion and knowledge factors.
/// @param password Password used for the knowledge factor.
/// @return New instance of authentication object configured for signing with a possession and knowledge factors.
+ (nonnull PowerAuthAuthentication *) possessionWithPassword:(nonnull NSString*)password
						NS_SWIFT_NAME(possessionWithPassword(password:));

/// Create a new instance of authentication object preconfigured for combination of possesion and knowledge factors, with using custom possession key.
/// @param password Password used for the knowledge factor.
/// @param customPossessionKey Custom key used for possession factor.
/// @return New instnace of authentication object configured for signing with custom possession key and knowledge factor.
+ (nonnull PowerAuthAuthentication *) possessionWithKnowledge:(nonnull NSString*)password
										 customPossessionKey:(nonnull NSData*)customPossessionKey
						NS_SWIFT_NAME(possessionWithPassword(password:customPossessionKey:));

// Deprecated variants

/// Create a new instance of authentication object preconfigured for signign with combination of possession and biometry factors and with prompt,
/// displayed in the system biometric authentication dialog.
///
/// This method is deprecated in favor to `possessionWithBiometry(prompt:)`.
///
/// @param biometryPrompt Prompt displayed in the system biometric authentication dialog.
/// @return New instance of authentication object configured for signing with a possession and biometry factors, with custom prompt displayed in the system biometric authentication dialog.
+ (nonnull PowerAuthAuthentication *) possessionWithBiometryWithPrompt:(nonnull NSString*)biometryPrompt PA2_DEPRECATED(1.7.0);

/// Create a new instance of authentication object preconfigured for combination of possesion and knowledge factors.
///
/// This method is deprecated in favor to `possessionWithPassword(password:)`.
///
/// @param password Password used for the knowledge factor.
/// @return New instance of authentication object configured for signing with a possession and knowledge factors.
///
+ (nonnull PowerAuthAuthentication *) possessionWithPasswordDeprecated:(nonnull NSString*)password
						NS_SWIFT_NAME(possession(withPassword:))
						PA2_DEPRECATED(1.7.0);
@end
