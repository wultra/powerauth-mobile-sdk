/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
#import "PA2Error.h"
#import "PA2Response.h"

/** Class representing an error PowerAuth 2.0 Standard API response.
 */
@interface PA2ErrorResponse : NSObject

@property (nonatomic, assign) PA2RestResponseStatus status;
@property (nonatomic, assign) NSUInteger httpStatusCode;
@property (nonatomic, strong) PA2Error* responseObject;

/** Initialize a new error response with a single error object.
 
 @param error An error instance.
 @return New error response with given error.
 */
- (instancetype)initWithError:(PA2Error*)error;

/** Initializes a new error response from given dictionary (as it is received from PowerAuth 2.0 Standard RESTful API) using a given response object type.
 
 @param dictionary A dictionary with response object information.
 @return New PAErrorResponse instance.
 */
- (instancetype)initWithDictionary:(NSDictionary *)dictionary;


@end
