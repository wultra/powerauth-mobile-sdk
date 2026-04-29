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

#import "PA2Response.h"
#import "PA2PrivateMacros.h"

@implementation PA2Response

- (instancetype) initWithDictionary:(NSDictionary *)dictionary responseObjectType:(Class)responseObjectType
{
    self = [super init];
    if (self) {
        // Handle response status
        NSString * statusString         = PA2ObjectAs(dictionary[@"status"], NSString);
        NSDictionary * objectDictionary = PA2ObjectAs(dictionary[@"responseObject"], NSDictionary);
        // Check status
        if ([statusString isEqualToString:@"OK"]) {
            // Deserialize expected response object type
            _status = PowerAuthRestApiResponseStatus_OK;
            _responseObject = [[responseObjectType alloc] initWithDictionary:objectDictionary];
        } else {
            // Deserialize error object
            _status = PowerAuthRestApiResponseStatus_ERROR;
            // TODO: looks like we're not using this property at all.
            _responseError = [[PowerAuthRestApiError alloc] initWithDictionary:objectDictionary];
        }
    }
    return self;
}

@end
