/**
 * Copyright 2016 Wultra s.r.o.
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

#import "PA2System.h"
#import "PA2Session.h"
#import "PA2Log.h"

#import <UIKit/UIKit.h>

#include <sys/utsname.h>
#include "TargetConditionals.h"

BOOL pa_isJailbroken() {
#if !(TARGET_IPHONE_SIMULATOR)
	
	if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]
		|| [[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"]
		|| [[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"]
		|| [[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"]
		|| [[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"]
		|| [[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/lib/apt/"]
		|| [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]])  {
		return YES;
	}
	
	FILE *f = NULL ;
	if ((f = fopen("/bin/bash", "r"))
		|| (f = fopen("/Applications/Cydia.app", "r"))
		|| (f = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "r"))
		|| (f = fopen("/usr/sbin/sshd", "r"))
		|| (f = fopen("/etc/apt", "r")))  {
		fclose(f);
		return YES;
	}
	fclose(f);
	
	NSError *error;
	NSString *stringToBeWritten = @"This is a test.";
	[stringToBeWritten writeToFile:@"/private/jailbreak.txt" atomically:YES encoding:NSUTF8StringEncoding error:&error];
	[[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak.txt" error:nil];
	if(error == nil) {
		return YES;
	}
	
#endif
	
	return NO;
}

@implementation PA2System

+ (BOOL) isInDebug {
	BOOL result = [PA2Session hasDebugFeatures];
#if defined(ENABLE_PA2_LOG) || defined(DEBUG)
	result |= YES;
#endif
	return result;
}

// TODO: We should remove this objc method. The public documentation says that if you want to slow down the attacker, then
//       you should use the C function. But the fun fact is, that we're actually helping find that function. Look at
//       the assembly code, produced for the release build:
//
//		 +[PA2System isJailbroken]:
//    	     0x126222f8d <+0>: pushq  %rbp
//    	     0x126222f8e <+1>: movq   %rsp, %rbp
//		 ->  0x126222f91 <+4>: popq   %rbp
//           0x126222f92 <+5>: jmp    0x126222bd4               ; pa_isJailbroken at PA2System.m:21
//
//       So, the long term plan is to remove this feature from the SDK and have a separate library for jailbreak detection.
+ (BOOL) isJailbroken {
	return pa_isJailbroken();
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
		PA2Log(@"PA2System.deviceInfo: uname() failed with code %d", errno);
		return @"iDeviceUnknown";
	}
	return [NSString stringWithUTF8String:utsname.machine];
 #else
	return @"simulator";
#endif
}

@end
