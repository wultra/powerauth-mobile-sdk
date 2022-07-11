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

#import <PowerAuth2/PowerAuthAuthentication.h>

@interface PowerAuthAuthentication (Private)
/**
 Contains numeric value representing a combination of used factors.
 */
@property (nonatomic, readonly) NSInteger signatureFactorMask;

/// Function validates whether PowerAuthAuthentication was created for the right object usage.
/// @param forCommit Specifies whether commit or sign operation is required.
/// @return YES if object is correct for the specified usage.
- (BOOL) validateUsage:(BOOL)forCommit;

@end
