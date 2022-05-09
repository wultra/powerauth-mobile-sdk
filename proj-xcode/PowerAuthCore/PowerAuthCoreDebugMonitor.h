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

#import <PowerAuthCore/PowerAuthCoreTypes.h>

#if DEBUG
/**
 The `PowerAuthCoreDebugMonitor` is a helper protocol that allows you detect and debug
 various low-level interface misuses. The interface is not used if core is compiled
 for the release configuration.
 */
@protocol PowerAuthCoreDebugMonitor <NSObject>

/**
 Called when operation require a write access granted to the shared data.
 */
- (void) requireWriteAccess;

/**
 Called when operation requre a read access granted to the shared data.
 */
- (void) requireReadAccess;

/**
 Called when the operation failed with an error code. The operation name is an additional information
 useful for debug purposes.
 */
- (void) reportErrorCode:(PowerAuthCoreErrorCode)errorCode forOperation:(nullable NSString*)operationName;

@end

#else
/**
 The `PowerAuthCoreDebugMonitor` is empty for RELEASE build.
 */
#define PowerAuthCoreDebugMonitor NSObject
#endif
