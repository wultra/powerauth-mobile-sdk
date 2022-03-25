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

@interface PA2Result<ResultType> : NSObject

@property (nonatomic, readonly, strong, nullable) NSError * error;
@property (nonatomic, readonly, strong, nullable) ResultType result;
@property (nonatomic, readonly, strong, nullable) id associatedData;

+ (nonnull PA2Result<ResultType>*) success:(nonnull ResultType)result;
+ (nonnull PA2Result<ResultType>*) failure:(nonnull NSError*)failure;

- (nonnull PA2Result<ResultType>*) withAssociatedData:(id _Nullable)associatedData;

- (nullable ResultType) extractResult:(NSError* _Nullable* _Nullable)error;

@end

