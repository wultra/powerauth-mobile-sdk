/**
 * Copyright 2018 Wultra s.r.o.
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

/**
 The `PA2HttpRequestInterceptor` protocol defines interface for modifying HTTP requests
 before their execution.
 
 WARNING
 
 This protocol allows you to tweak the requests created in the PowerAuthSDK, but
 also gives you an opportunity to break the things. So, rather than create your own interceptor,
 try to contact us and describe what's your problem with the networking in the PowerAuth SDK.
 
 Also note, that this interface may change in the future. We can guarantee the API stability of
 public classes implementing this interface, but not the stability of interface itself.
 */
@protocol PA2HttpRequestInterceptor <NSObject>

/**
 Method is called by the PA2HttpClient, before the request is executed.
 The implementation must count with that method is called from other than UI thread.
 
 @param request URL request to be modified.
 */
- (void) processRequest:(nonnull NSMutableURLRequest*)request;

@end
