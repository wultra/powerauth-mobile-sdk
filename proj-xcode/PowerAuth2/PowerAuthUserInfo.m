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

#import "PowerAuthUserInfo+Private.h"
#import "PA2PrivateMacros.h"
#import "PowerAuthLog.h"

@implementation PowerAuthUserInfo

#pragma mark - Support functions

// Simple string getter
#define CLAIMS_GETTER(propertyName, claimName)      \
    - (NSString *) propertyName { return PA2ObjectAs(_allClaims[claimName], NSString); }

// Getter for multi-line string, patching MS-DOS newlines.
inline static NSString * _GetterMLString(id object)
{
    NSString * s = PA2ObjectAs(object, NSString);
    return [s stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
}
#define CLAIMS_GETTER_ML(propertyName, claimName)      \
    - (NSString *) propertyName { return _GetterMLString(_allClaims[claimName]); }

// Simple BOOL getter
#define CLAIMS_GETTER_BOOL(propertyName, claimName) \
    - (BOOL) propertyName { return [PA2ObjectAs(_allClaims[claimName], NSNumber) boolValue]; }

// Getter for returning timestamp
inline static NSDate * _GetterTimestamp(id object)
{
    NSNumber * n = PA2ObjectAs(object, NSNumber);
    return n ? [NSDate dateWithTimeIntervalSince1970:[n doubleValue]] : nil;
}
#define CLAIMS_GETTER_TIMESTAMP(propertyName, claimName)      \
    - (NSDate *) propertyName { return _GetterTimestamp(_allClaims[claimName]); }


#pragma mark - Initialization

- (instancetype) initWithDictionary:(NSDictionary<NSString*, NSObject*>*)dictionary
{
    if (!dictionary) {
        return nil;
    }
    self = [super init];
    if (self) {
        // Keep the whole dictionary.
        _allClaims = dictionary;
        // "birthdate"
        NSString * birthDate = PA2ObjectAs(dictionary[@"birthdate"], NSString);
        if (birthDate) {
            NSDateFormatter * formatter = [[NSDateFormatter alloc] init];
            formatter.dateFormat = @"yyyy-MM-dd";
            _birthdate = [formatter dateFromString:birthDate];
        }
        // "address"
        NSDictionary * address = PA2ObjectAs(dictionary[@"address"], NSDictionary);
        _address = [[PowerAuthUserAddress alloc] initWithDictionary:address];
    }
    return self;
}

#pragma mark - Getters

CLAIMS_GETTER(subject, @"sub")
CLAIMS_GETTER(name, @"name")
CLAIMS_GETTER(givenName, @"given_name")
CLAIMS_GETTER(familyName, @"family_name")
CLAIMS_GETTER(middleName, @"middle_name")
CLAIMS_GETTER(nickname, @"nickname")
CLAIMS_GETTER(preferredUsername, @"preferred_username")
CLAIMS_GETTER(profileUrl, @"profile")
CLAIMS_GETTER(pictureUrl, @"picture")
CLAIMS_GETTER(websiteUrl, @"website")
CLAIMS_GETTER(email, @"email")
CLAIMS_GETTER(phoneNumber, @"phone_number")
CLAIMS_GETTER_BOOL(isEmailVerified, @"email_verified")
CLAIMS_GETTER_BOOL(isPhoneNumberVerified, @"phone_number_verified")
CLAIMS_GETTER(gender, @"gender")
CLAIMS_GETTER(zoneInfo, @"zoneinfo")
CLAIMS_GETTER(locale, @"locale")
CLAIMS_GETTER_TIMESTAMP(updatedAt, @"updated_at")

#ifdef DEBUG
- (NSString*) description
{
    return [NSString stringWithFormat:@"<PowerAuthUserInfo: %@>", _allClaims];
}
#endif // DEBUG

@end


@implementation PowerAuthUserAddress

- (instancetype) initWithDictionary:(NSDictionary<NSString*, NSObject*>*)dictionary
{
    if (!dictionary) {
        return nil;
    }
    self = [super init];
    if (self) {
        _allClaims = dictionary;
    }
    return self;
}

CLAIMS_GETTER_ML(formatted, @"formatted")
CLAIMS_GETTER_ML(street, @"street_address")
CLAIMS_GETTER(locality, @"locality")
CLAIMS_GETTER(region, @"region")
CLAIMS_GETTER(postalCode, @"postal_code")
CLAIMS_GETTER(country, @"country")

#ifdef DEBUG
- (NSString*) description
{
    return [NSString stringWithFormat:@"<PowerAuthUserAddress: %@>", _allClaims];
}
#endif // DEBUG

@end
