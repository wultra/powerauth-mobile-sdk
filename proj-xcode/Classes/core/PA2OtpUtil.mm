/**
 * Copyright 2016-2017 Wultra s.r.o.
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

#import <PowerAuth/OtpUtil.h>
#import <cc7/objc/ObjcHelper.h>

#import "PA2OtpUtil.h"

using namespace io::getlime::powerAuth;

@implementation PA2Otp
{
	OtpComponents _components;
}

- (id) initWithOtpComponents:(const OtpComponents &)components
{
	self = [super init];
	if (self) {
		_components = components;
	}
	return self;
}

- (NSString*) activationCode
{
	return cc7::objc::CopyToNSString(_components.activationCode);
}

- (NSString*) activationSignature
{
	return cc7::objc::CopyToNullableNSString(_components.activationSignature);
}

@end



@implementation PA2OtpUtil

+ (BOOL) validateTypedCharacter:(UInt32)character
{
	return OtpUtil::validateTypedCharacter(character);
}

+ (UInt32) validateAndCorrectTypedCharacter:(UInt32)character
{
	return OtpUtil::validateAndCorrectTypedCharacter(character);
}

+ (BOOL) validateActivationCode:(NSString*)activationCode
{
	return OtpUtil::validateActivationCode(cc7::objc::CopyFromNSString(activationCode));
}

+ (PA2Otp*) parseFromActivationCode:(NSString*)activationCode
{
	auto cppActivationCode = cc7::objc::CopyFromNSString(activationCode);
	OtpComponents cppComponents;
	if (OtpUtil::parseActivationCode(cppActivationCode, cppComponents)) {
		return [[PA2Otp alloc] initWithOtpComponents:cppComponents];
	}
	return nil;
}

@end
