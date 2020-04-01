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

#import <Foundation/Foundation.h>

/**
 Checks if the device is jailbroken.
 
 @return YES if the device is jailbroken, NO otherwise.
 */
extern BOOL pa_isJailbroken(void);

@interface PA2System : NSObject

/**
 Detects if the PowerAuth SDK is compiled with debug features.
 
 @return YES if library uses debug features, NO otherwise.
 */
+ (BOOL) isInDebug;

/**
 Checks if the device is jailbroken.
 
 Please not that this method is exposed as an Objective-C method and as such, it can be very easily detected and bypassed.
 As a result, this method is very good for basic checks for example for educational purpose (to tell users that jailbreaking
 is a bad idea) but it will not stop a skilled attacker from bypassing the check.
 
 If this is an issue for you and if you use Objective-C, you can use `pa_isJailbroken()` inline method which is slightly
 stronger in this aspect. Generally speaking, there is no way to aviod jailbreak detection alltogether, so you shoudl stick
 with using this method for "educational check".
 
 @return YES if the device is jailbroken, NO otherwise.
 */
+ (BOOL) isJailbroken;

/**
 Returns string representing the current device's platform (e.g. "ios", "tvos", etc.)
 */
+ (nonnull NSString*) platform;

/**
 Returns more detailed information about the device (e.g. "iPhone12,3")
 */
+ (nonnull NSString*) deviceInfo;

@end
