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

#import <Foundation/Foundation.h>

/**
 The `PA2AppGroupContainer` wraps various functionality related to app groups.
 */
@interface PA2AppGroupContainer : NSObject

/**
 Create container object with given app group identifier.
 */
+ (nullable PA2AppGroupContainer*) containerWithAppGroup:(nonnull NSString*)appGroup;

/**
 Contains app group identifier.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * appGroup;

/**
 Contains URL with path to directory shared between vendor's apps.
 */
@property (nonatomic, strong, nonnull, readonly) NSURL * containerUrl;

/**
 Return path to lock file stored in this container. The real file name is calculated as
 `"PowerAuthSharedLock-" + SHA256(lockIdentifier).base64String` where Base64 string is
 with no padding characters.
 */
- (nullable NSString*) pathToFileLockWithIdentifier:(nonnull NSString*)lockIdentifier;

@end
