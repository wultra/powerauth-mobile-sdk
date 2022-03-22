/*
 * Copyright 2022 Wultra s.r.o.
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

#import "PA2AppGroupContainer.h"
#import <PowerAuth2/PowerAuthLog.h>

@import PowerAuthCore;

@implementation PA2AppGroupContainer

- (nullable instancetype) initWithAppGroup:(nonnull NSString*)appGroup
							  containerUrl:(nonnull NSURL*)containerUrl
{
	self = [super init];
	if (self) {
		_containerUrl = containerUrl;
		_appGroup = appGroup;
	}
	return self;
}

+ (nullable PA2AppGroupContainer*) containerWithAppGroup:(nonnull NSString*)appGroup;
{
	// Acquire URL with path to the shared directory.
	NSURL * containerUrl = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:appGroup];
	if (!containerUrl) {
		PowerAuthLog(@"PA2AppGroupContainer: Failed to get container URL for app group '%@'", appGroup);
		return nil;
	}
	// Create container
	return [[PA2AppGroupContainer alloc] initWithAppGroup:appGroup containerUrl: containerUrl];
}

- (nullable NSString*) pathToFileLockWithIdentifier:(nonnull NSString*)lockIdentifier
{
	// Calculate hash from identifier.
	NSString * fullIdentifier = [[[PowerAuthCoreCryptoUtils hashSha256:[lockIdentifier dataUsingEncoding:NSUTF8StringEncoding]]
								  base64EncodedStringWithOptions:0]
								 substringToIndex:43];	// remove trailing '=' character
	
	// Build lock file name as "PowerAuthSharedLock-" + SHA256(lockIdentifier).base64String
	NSString * lockFile = [@"PowerAuthSharedLock-" stringByAppendingString:fullIdentifier];
	// Locate file in container
	NSURL * fileUrl = [_containerUrl URLByAppendingPathComponent:lockFile isDirectory:NO];
	if (!fileUrl) {
		PowerAuthLog(@"PA2AppGroupContainer: Failed to build lock file path. App group '%@', lockFile '%@'", _appGroup, lockFile);
		return nil;
	}
	return fileUrl.path;
}

@end
