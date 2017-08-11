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

#import "PA2Response.h"
#import "PA2Error.h"

@implementation PA2Response

- (instancetype)initWithDictionary:(NSDictionary *)dictionary responseObjectType:(Class)responseObjectType {
    self = [super init];
    if (self) {
		
		// Handle response status
		NSString *statusString = [[dictionary objectForKey:@"status"] lowercaseString];
		if ([statusString isEqualToString:@"ok"]) {
			_status = PA2RestResponseStatus_OK;
			
			// Serialize OK response object
			_responseObject = [[responseObjectType alloc] initWithDictionary:[dictionary objectForKey:@"responseObject"]];
			
		} else {
			_status = PA2RestResponseStatus_ERROR;
			
			// Serialize error response object
			_responseObject = [[PA2Error alloc] initWithDictionary:[dictionary objectForKey:@"responseObject"]];
		}
		
    }
    return self;
}

@end
