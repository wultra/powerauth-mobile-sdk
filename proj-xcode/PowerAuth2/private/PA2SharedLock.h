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
 The `PA2SharedLock` implements `NSLocking` protocol and allows you
 to acquire an exclusive access to the resources shared between the multiple
 apps.
 */
@interface PA2SharedLock : NSObject<NSLocking>

/**
 Initialize  interprocess lock with full path to file used for locking.
 If recursive parameter is YES, then reentrant lock is created, so you can acquire lock
 for multiple times from the same thread.
 */
- (nullable instancetype) initWithPath:(nonnull NSString*)path
                             recursive:(BOOL)recursive;

/**
 Attempts to acquire a lock, and immediately returns a Boolean value that indicates
 whether the attempt was successful.
 */
- (BOOL) tryLock;

/**
 If shared lock was initialized with the recursive flag, then this function instantiate
 a new object implementing NSLocking protocol that allows you acquire the same recursive
 lock that use PA2SharedLock internally. By calling lock and unlock on this object, you can
 synchronize the access to shared resources, but only for this process.
 */
- (nullable id<NSLocking>) createLocalRecusiveLock;

@end
