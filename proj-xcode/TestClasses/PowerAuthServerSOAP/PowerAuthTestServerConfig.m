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

/**
 The `POWERAUTH_BASE_URL` macro defines a base URL where are the running server instances
 located. The default config expects that the SOAP & REST servers are running at "http://paserver"
 domain. If you're using a locally installed docker, then more common for you
 will be set the base URL to "http://localhost". 
 
 NOTE: You should create a local configuration file instead of changing this source file.
        Check TestConfig/Readme.md for details.
 */
#ifndef POWERAUTH_BASE_URL
#define POWERAUTH_BASE_URL @"http://localhost"
#endif


@implementation PowerAuthTestServerConfig

+ (instancetype) defaultConfig
{
	NSDictionary * dict =
	@{
	  @"restApiUrl"           : POWERAUTH_BASE_URL @":13030/powerauth-webauth",
	  @"soapApiUrl"           : POWERAUTH_BASE_URL @":20010/powerauth-java-server/soap",
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

+ (instancetype) loadFromDictionary:(NSDictionary*)dict
{
	PowerAuthTestServerConfig * instance = [[PowerAuthTestServerConfig alloc] init];
	if (instance) {
		instance->_restApiUrl = dict[@"restApiUrl"];
		instance->_soapApiUrl = dict[@"soapApiUrl"];
		instance->_powerAuthAppName = dict[@"powerAuthAppName"];
		instance->_powerAuthAppVersion = dict[@"powerAuthAppVersion"];
		instance->_userIdentifier = dict[@"userIdentifier"];
		instance->_userActivationName = dict[@"userActivationName"];
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

@end
