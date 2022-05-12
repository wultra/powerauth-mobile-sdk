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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import <PowerAuth2ForExtensions/PowerAuthMacros.h>

/**
 The `PA2TokenDataLock` defines interface that allows token store
 acquire an exclusive access to shared token data.
 */
@protocol PA2TokenDataLock <NSObject>

/**
 Lock token store data and return whether the local cached context
 should be invalidated.
 */
- (BOOL) lockTokenStore;

/**
 Unlock token store data and mark that token store has been modified.
 */
- (void) unlockTokenStore:(BOOL)contentModified;

@end
