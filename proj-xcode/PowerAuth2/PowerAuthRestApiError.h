/**
 * Copyright 2021 Wultra s.r.o.
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
 Class representing an error in the RESTful API.
 */
@interface PowerAuthRestApiError : NSObject

/** Error code
 */
@property (nonatomic, strong) NSString *code;

/** Error message
 */
@property (nonatomic, strong) NSString *message;

/**
 Contains additional information received together with error.
 */
@property (nonatomic, strong) NSDictionary *additionalInfo;

@end


@interface PowerAuthRestApiError (RecoveryCode)

/**
 Contains an index of valid PUK in case that recovery activation did fail and
 there's still some recovery PUK available.
 
 The property contains -1 if the information is not available in the error response.
 */
@property (nonatomic, readonly, assign) NSInteger currentRecoveryPukIndex;

@end
