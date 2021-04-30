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

#import "PowerAuthSystem.h"
#import "PowerAuthLog.h"

#include <sys/utsname.h>
#include "TargetConditionals.h"

#if PA2_HAS_CORE_MODULE
@import PowerAuthCore;
#define _CoreModuleIsDebug() [PowerAuthCoreSession hasDebugFeatures]
#else
#define _CoreModuleIsDebug() NO
#endif

@implementation PowerAuthSystem

+ (BOOL) isInDebug {
	BOOL result = _CoreModuleIsDebug();
#if defined(ENABLE_PA2_LOG) || defined(DEBUG)
	result |= YES;
#endif
	return result;
}

+ (NSString*) platform
{
#if TARGET_OS_OSX == 1
	return @"macOS";
#elif TARGET_OS_IOS == 1
	return @"iOS";
#elif TARGET_OS_WATCH == 1
	return @"watchOS";
#elif TARGET_OS_TV == 1
	return @"tvOS";
#elif TARGET_OS_MACCATALYST == 1
	return "macCatalyst";
#else
	unknown_platform // Compilation must fail here.
#endif
}

+ (NSString*) deviceInfo
{
#if TARGET_OS_SIMULATOR == 0
	struct utsname utsname;
	int err = uname(&utsname);
	if (err != 0) {
		PowerAuthLog(@"PA2System.deviceInfo: uname() failed with code %d", errno);
		return @"iDeviceUnknown";
	}
	return [NSString stringWithUTF8String:utsname.machine];
 #else
	return @"simulator";
#endif
}

@end
