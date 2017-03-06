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
#import "PA2NetworkObject.h"

/** Enum representing the response status: ok, or error
 */
typedef NS_ENUM(int, PA2RestResponseStatus) {
	PA2RestResponseStatus_OK = 0,
	PA2RestResponseStatus_ERROR = 1
};

/** Enum representing a used encryption type: non, personalized, or non-personalized.
 */
typedef NS_ENUM(int, PA2RestResponseEncryption) {
	PA2RestResponseEncryption_None = 0,
	PA2RestResponseEncryption_NonPersonalized = 1,
	PA2RestResponseEncryption_Personalized = 2
};

/** Class representing a generic PowerAuth 2.0 Standard API response.
 
 Client classes are supposed to create a new object using 'initWithDictionary:responseObjectType:' method and serialize response objects using 'toDictionary' method.
 */
@interface PA2Response<T> : NSObject

@property (nonatomic, assign) PA2RestResponseStatus status;
@property (nonatomic, assign) PA2RestResponseEncryption encryption;

@property (nonatomic, strong) T<PA2NetworkObject> responseObject;

/** Initializes a new response from given dictionary (as it is received from PowerAuth 2.0 Standard RESTful API) using a given response object type.
 
 @param dictionary A dictionary with response object information.
 @param responseObjectType Class of the response Object type.
 @return New instance of PAResponse class.
 */
- (instancetype)initWithDictionary:(NSDictionary<NSString*, NSObject*>*)dictionary responseObjectType:(Class)responseObjectType;

@end
