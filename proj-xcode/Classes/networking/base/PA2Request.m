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

#import "PA2Request.h"

@implementation PA2Request

- (NSDictionary *)toDictionary {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	
	// serialize encryption type
	if (_encryption == PA2RestRequestEncryption_Personalized) {
		[dictionary setObject:@"personalized" forKey:@"encryption"];
	} else if (_encryption == PA2RestRequestEncryption_NonPersonalized) {
		[dictionary setObject:@"nonpersonalized" forKey:@"encryption"];
	} else {
		[dictionary setObject:@"none" forKey:@"encryption"];
	}
	
	// serialize request object
    [dictionary setObject:[_requestObject toDictionary] forKey:@"requestObject"];
    return dictionary;
}

@end
