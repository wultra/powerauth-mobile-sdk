/*
 * Copyright 2017 Juraj Durech <durech.juraj@gmail.com>
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

#import "PowerAuthTestServerConfig.h"
#import <UIKit/UIDevice.h>

@implementation PowerAuthTestServerConfig

+ (instancetype) defaultConfig
{
    NSDictionary * dict =
    @{
      @"restApiUrl"           : @"http://localhost:8080/powerauth-webauth",
      @"soapApiUrl"           : @"http://localhost:8080/powerauth-java-server/soap",
      @"soapApiVersion"       : @"1.1",
      @"powerAuthAppName"     : @"AutomaticTest-IOS",
      @"powerAuthAppVersion"  : @"default"
      
    };
    return [self loadFromDictionary:dict];
}

+ (instancetype) loadFromJsonFile:(NSString *)path
{
    NSError * error = nil;
    NSData * data = [NSData dataWithContentsOfFile:path options:0 error:&error];
    if (!data || error) {
        NSLog(@"%@: Unable to load configuration file. Error: %@", [self class], error.localizedDescription);
        return nil;
    }
    id object = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingAllowFragments error:&error];
    if (!object || error) {
        NSLog(@"%@: The configuration JSON is invalid. Error: %@", [self class], error.localizedDescription);
        return nil;
    }
    if (![object isKindOfClass:[NSDictionary class]]) {
        NSLog(@"%@: The configuration JSON must contain a dictionary with options.", [self class]);
        return nil;
    }
    return [self loadFromDictionary:object];
}

PowerAuthProtocolVersion PATSProtoVer(PowerAuthTestServerVersion serverVer)
{
    switch (serverVer) {
        case PATS_V0_18:
            return PATS_P2;
        case PATS_V0_21:
        case PATS_V0_22:
        case PATS_V0_22_2:
            return PATS_P3;
        case PATS_V0_23:
        case PATS_V0_23_2:
        case PATS_V0_24:
        case PATS_V1_0:
        case PATS_V1_1:
        case PATS_V1_2:
        case PATS_V1_2_5:
        case PATS_V1_3:
        case PATS_V1_4:
        case PATS_V1_5:
            return PATS_P31;
        default:
            // Older versions, defaulting to V2
            return PATS_P2;
    }
}

+ (PowerAuthTestServerVersion) soapApiVersionFromString:(NSString*)stringVersion
{
    static NSDictionary * versionMapping = nil;
    if (versionMapping == nil) {
        versionMapping = @{
            @"0.18"   : @(PATS_V0_18),
            @"0.19"   : @(PATS_V0_18),
            @"0.20"   : @(PATS_V0_18),
            @"0.21"   : @(PATS_V0_21),
            @"0.22"   : @(PATS_V0_22),
            @"0.22.1" : @(PATS_V0_22),
            @"0.22.2" : @(PATS_V0_22_2),
            @"0.23"   : @(PATS_V0_23),
            @"0.23.1" : @(PATS_V0_23),
            @"0.23.2" : @(PATS_V0_23_2),
            @"0.24"   : @(PATS_V0_24),
            @"1.0"    : @(PATS_V1_0),
            @"1.1"    : @(PATS_V1_1),
            @"1.2"    : @(PATS_V1_2),
            @"1.2.5"  : @(PATS_V1_2_5),
            @"1.3"    : @(PATS_V1_3),
            @"1.4"    : @(PATS_V1_4),
            @"1.5"    : @(PATS_V1_5),
         };
    }
    // Remove "V" character from the beginning of the string.
    NSString * ver = [stringVersion lowercaseString];
    if ([ver characterAtIndex:0] == 'v') {
        ver = [ver substringFromIndex:1];
    }
    NSNumber * version = versionMapping[ver];
    if (version) {
        return [version intValue];
    }
    // Older versions, defaulting to 0.18
    NSLog(@"%@: Unknown soapApiVersion '%@'. Defaulting to V0.18", [self class], stringVersion);
    return PATS_V0_18;
}

+ (instancetype) loadFromDictionary:(NSDictionary*)dict
{
    PowerAuthTestServerConfig * instance = [[PowerAuthTestServerConfig alloc] init];
    if (instance) {
        instance->_restApiUrl = dict[@"restApiUrl"];
        instance->_soapApiUrl = dict[@"soapApiUrl"];
        instance->_soapAuthUsername = dict[@"soapAuthUsername"];
        instance->_soapAuthPassword = dict[@"soapAuthPassword"];
        instance->_soapApiVersion = [self soapApiVersionFromString:dict[@"soapApiVersion"]];
        instance->_powerAuthAppName = dict[@"powerAuthAppName"];
        instance->_powerAuthAppVersion = dict[@"powerAuthAppVersion"];
        instance->_userIdentifier = dict[@"userIdentifier"];
        instance->_userActivationName = dict[@"userActivationName"];
        instance->_isServerAutoCommit = [dict[@"serverAutoCommit"] boolValue];
        instance->_configDictionary = [dict copy];
        if (![instance validateAndFillOptionals]) {
            return nil;
        }
    }
    return instance;
}

- (BOOL) validateAndFillOptionals
{
    if (!_soapApiUrl || !_restApiUrl) {
        NSLog(@"%@: missing requred URLS.", [self class]);
        return NO;
    }
    if (nil == [NSURL URLWithString:_restApiUrl]) {
        NSLog(@"%@: restApiUrl is wrong.", [self class]);
        return NO;
    }
    if (nil == [NSURL URLWithString:_soapApiUrl]) {
        NSLog(@"%@: soapApiUrl is wrong.", [self class]);
        return NO;
    }
    if (nil == _powerAuthAppName) {
        _powerAuthAppName = @"AutomaticTest-IOS";
    }
    if (nil == _powerAuthAppVersion) {
        _powerAuthAppVersion = @"default";
    }
    if (nil == _userIdentifier) {
        _userIdentifier = @"TestUserIOS";
    }
    if (nil == _userActivationName) {
        _userActivationName = [self.class buildDefaultActivationName];
    }
    return YES;
}

+ (NSString*) buildDefaultActivationName
{
    UIDevice * dev = [UIDevice currentDevice];
    return [NSString stringWithFormat:@"Testing on '%@', %@, %@ %@", dev.name, dev.model, dev.systemName, dev.systemVersion];
}

- (id) configValueForKey:(NSString*)key defaultValue:(id)defaultValue
{
    id value = [_configDictionary objectForKey:key];
    return value != nil ? value : defaultValue;
}

@end
