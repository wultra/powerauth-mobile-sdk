/*
 * Copyright 2023 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthMacros.h>

@class PowerAuthUserAddress;

/// The `PowerAuthUserInfo` object contains additional information about the end-user.
@interface PowerAuthUserInfo : NSObject

/// The subject (end-user) identifier.
@property (nonatomic, readonly, nullable) NSString * subject;
/// The full name of the end-user.
@property (nonatomic, readonly, nullable) NSString * name;
/// The given or first name of the end-user.
@property (nonatomic, readonly, nullable) NSString * givenName;
/// The surname(s) or last name(s) of the end-user.
@property (nonatomic, readonly, nullable) NSString * familyName;
/// The middle name of the end-user.
@property (nonatomic, readonly, nullable) NSString * middleName;
/// The casual name of the end-user.
@property (nonatomic, readonly, nullable) NSString * nickname;
/// The username by which the end-user wants to be referred to at the client application.
@property (nonatomic, readonly, nullable) NSString * preferredUsername;
/// The URL of the profile page for the end-user.
@property (nonatomic, readonly, nullable) NSString * profileUrl;
/// The URL of the profile picture for the end-user.
@property (nonatomic, readonly, nullable) NSString * pictureUrl;
/// The URL of the end-user's web page or blog.
@property (nonatomic, readonly, nullable) NSString * websiteUrl;
/// The end-user's preferred email address.
@property (nonatomic, readonly, nullable) NSString * email;
/// True if the end-user's email address has been verified, else false.
/// Note that value is false also when claim is not present in `claims` dictionary.
@property (nonatomic, readonly) BOOL isEmailVerified;
/// The end-user's preferred telephone number, typically in E.164 format, for example `+1 (425) 555-1212`
/// or `+56 (2) 687 2400`.
@property (nonatomic, readonly, nullable) NSString * phoneNumber;
/// True if the end-user's telephone number has been verified, else false.
/// Note that value is false also when claim is not present in `claims` dictionary.
@property (nonatomic, readonly) BOOL isPhoneNumberVerified;
/// The end-user's gender.
@property (nonatomic, readonly, nullable) NSString * gender;
/// The end-user's birthday.
@property (nonatomic, readonly, nullable) NSDate * birthdate;
/// The end-user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles`.
@property (nonatomic, readonly, nullable) NSString * zoneInfo;
/// The end-user's locale, represented as a BCP47 language tag. This is typically an ISO 639-1 Alpha-2
/// language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash.
/// For example, `en-US` or `fr-CA`.
@property (nonatomic, readonly, nullable) NSString * locale;
/// An object describing the end-user's preferred postal address.
@property (nonatomic, readonly, nullable) PowerAuthUserAddress * address;
/// Time the end-user's information was last updated.
@property (nonatomic, readonly, nullable) NSDate * updatedAt;

/// Contains full collection of standard claims received from the server.
@property (nonatomic, readonly, nonnull) NSDictionary<NSString*, NSObject*>* allClaims;

/// Construct object with claims dictionary.
/// - Parameter dictionary: Collection of standard claims.
- (nonnull instancetype) initWithDictionary:(nonnull NSDictionary<NSString*, NSObject*>*)dictionary
                            NS_SWIFT_NAME(init(with:));

@end

/// The `PowerAuthUserAddress` object contains address of end-user.
@interface PowerAuthUserAddress : NSObject

/// The full mailing address, with multiple lines if necessary.
@property (nonatomic, readonly, nullable) NSString * formatted;
/// The street address component, which may include house number, street name, post office box,
/// and other multi-line information.
@property (nonatomic, readonly, nullable) NSString * street;
/// City or locality component.
@property (nonatomic, readonly, nullable) NSString * locality;
/// State, province, prefecture or region component.
@property (nonatomic, readonly, nullable) NSString * region;
/// Zip code or postal code component.
@property (nonatomic, readonly, nullable) NSString * postalCode;
/// Country name component.
@property (nonatomic, readonly, nullable) NSString * country;

/// Contains full collection of standard claims received from the server.
@property (nonatomic, readonly, nonnull) NSDictionary<NSString*, NSObject*>* allClaims;

/// Construct object with claims dictionary.
/// - Parameter dictionary: Collection of standard claims.
- (nonnull instancetype) initWithDictionary:(nonnull NSDictionary<NSString*, NSObject*>*)dictionary
                            NS_SWIFT_NAME(init(with:));

@end
