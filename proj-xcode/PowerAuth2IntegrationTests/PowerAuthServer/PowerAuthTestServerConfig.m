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
        @"enrollmentUrl"        : @"http://localhost:8080/enrollment-server",
        @"serverApiUrl"         : @"http://localhost:8080/powerauth-java-server",
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
    if (serverVer >= PATS_V1_5) {
        return PATS_P32;
    }
    return PATS_P31;
}

static int s_KnownVersions[] = {
    PATS_V1_0, PATS_V1_1, PATS_V1_2, PATS_V1_2_5, PATS_V1_3, PATS_V1_4, PATS_V1_5,
    0
};

+ (PowerAuthTestServerVersion) apiVersionFromString:(NSString*)stringVersion
{
    NSString * snapshot = @"-SNAPSHOT";
    NSString * ver = [stringVersion hasSuffix:snapshot] ? [stringVersion substringToIndex:stringVersion.length - snapshot.length] : stringVersion;
    // Remove "V" character from the beginning of the string.
    ver = [ver lowercaseString];
    if ([ver characterAtIndex:0] == 'v') {
        ver = [ver substringFromIndex:1];
    }
    NSArray * components = [ver componentsSeparatedByString:@"."];
    if (components.count < 2) {
        @throw [NSException exceptionWithName:@"RestError" reason:[NSString stringWithFormat:@"Unknown server version %@", stringVersion] userInfo:nil];
    }
    NSNumber * major = components[0];
    NSNumber * minor = components[1];
    NSNumber * patch = components.count > 2 ? components[2] : nil;
    int version = [major intValue] * 10000 + [minor intValue] * 100 + [patch intValue];
    BOOL found = NO;
    int idx = 0;
    while (s_KnownVersions[idx]) {
        if (s_KnownVersions[idx++] == version) {
            found = YES;
            break;
        }
    }
    if (!found) {
        NSLog(@"Server version %@ is not defined. The server may be compatible with this test implementation.", stringVersion);
    }
    return version;
}

+ (instancetype) loadFromDictionary:(NSDictionary*)dict
{
    PowerAuthTestServerConfig * instance = [[PowerAuthTestServerConfig alloc] init];
    if (instance) {
        instance->_enrollmentUrl = dict[@"enrollmentUrl"];
        instance->_serverApiUrl = dict[@"serverApiUrl"];
        instance->_serverApiUsername = dict[@"serverApiUsername"];
        instance->_serverApiPassword = dict[@"serverApiPassword"];
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
    if (!_serverApiUrl || !_enrollmentUrl) {
        NSLog(@"%@: missing requred URLS.", [self class]);
        return NO;
    }
    if (nil == [NSURL URLWithString:_enrollmentUrl]) {
        NSLog(@"%@: restApiUrl is wrong.", [self class]);
        return NO;
    }
    if (nil == [NSURL URLWithString:_serverApiUrl]) {
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
