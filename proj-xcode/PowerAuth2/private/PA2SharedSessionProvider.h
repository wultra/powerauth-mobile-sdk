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

#import <PowerAuth2/PowerAuthCoreSessionProvider.h>
#import <PowerAuth2/PowerAuthConfiguration.h>

@import PowerAuthCore;

@class PA2SessionDataProvider;

/**
 The `PA2DefaultSessionProvider` provides PowerAuthCoreSession when
 interprocess session sharing is required.
 */
@interface PA2SharedSessionProvider : NSObject<PowerAuthCoreSessionProvider, PowerAuthCoreDebugMonitor>

/**
 Initialize provider with session and persistent data provider.
 */
- (nullable instancetype) initWithSession:(nonnull PowerAuthCoreSession *)session
							 dataProvider:(nonnull PA2SessionDataProvider *)dataProvider
							   instanceId:(nonnull NSString*)instanceId
							applicationId:(nonnull NSString*)applicationId
						   sharedMemoryId:(nonnull NSString *)sharedMemoryId
						   sharedLockPath:(nonnull NSString *)sharedLockPath;

@end

