/**
 * Copyright 2016 Wultra s.r.o.
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

@protocol PA2Encodable <NSObject>
/**
 Convert object instance to the dictionary.
 
 @return Current object converted to the dictionary.
 */
- (NSDictionary<NSString*, NSObject*>*) toDictionary;

@end

@protocol PA2Decodable <NSObject>

/**
 Initialize a new instance of object from a dictionary.
 
 @param dictionary Dictionary with the field related to object properties.
 @return New instance of object.
 */
- (instancetype) initWithDictionary:(NSDictionary<NSString*, NSObject*>*)dictionary;

@end
