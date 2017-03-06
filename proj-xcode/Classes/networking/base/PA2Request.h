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

/** Enum representing a used encryption type: non, personalized, or non-personalized.
 */
typedef NS_ENUM(int, PA2RestRequestEncryption) {
	PA2RestRequestEncryption_None = 0,
	PA2RestRequestEncryption_NonPersonalized = 1,
	PA2RestRequestEncryption_Personalized = 2
};

/** Class representing a generic PowerAuth 2.0 Standard API requests.
 
 Client classes are supposed to create a new object using 'initWithDictionary:requestObjectType:' method and serialize request objects using 'toDictionary' method.
 */
@interface PA2Request<T> : NSObject

@property (nonatomic, assign) PA2RestRequestEncryption encryption;

@property (nonatomic, strong) T<PA2NetworkObject> requestObject;

/** Serialize request object to the dictionary that is ready to be serialized to the correct JSON representation for the use in PowerAuth 2.0 Standard API.
 
 @return Dictionary representing the request object.
 */
- (NSDictionary<NSString*, NSObject*>*) toDictionary;

@end
