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

#import <PowerAuth2/PowerAuthMacros.h>

/**
 The `PA2Result` object wraps ResultType and NSError into one object.
 On top of that it allows you to associate any other object type to
 the arbitrary result.
 */
@interface PA2Result<ResultType> : NSObject
/**
 Contains result object in case that operation succeeded.
 */
@property (nonatomic, readonly, strong, nullable) ResultType result;
/**
 Contains error in case that operation failed.
 */
@property (nonatomic, readonly, strong, nullable) NSError * error;
/**
 Contains additional associated data.
 */
@property (nonatomic, readonly, strong, nullable) id associatedData;

/**
 Create result object with success.
 */
+ (nonnull PA2Result<ResultType>*) success:(nonnull ResultType)result;

/**
 Create result object with success and associated data.
 */
+ (nonnull PA2Result<ResultType>*) success:(nonnull ResultType)result
                                  withData:(nonnull id)data;
/**
 Create result object with failure.
 */
+ (nonnull PA2Result<ResultType>*) failure:(nonnull NSError*)failure;

/**
 Create result object with failure and associated data.
 */
+ (nonnull PA2Result<ResultType>*) failure:(nonnull ResultType)result
                                  withData:(nonnull id)data;

/**
 Create result object with failure or success. If both
 */
+ (nonnull PA2Result<ResultType>*) success:(nullable ResultType)result
                                 orFailure:(nullable NSError*)failure;

/**
 Return result and set error to provided NSError pointer in case result is failure.
 */
- (nullable ResultType) extractResult:(NSError* _Nullable* _Nullable)error;

@end

