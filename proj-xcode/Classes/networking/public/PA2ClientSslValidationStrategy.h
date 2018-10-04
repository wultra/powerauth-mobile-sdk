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

@protocol PA2ClientSslValidationStrategy <NSObject>

/**
 The method is called when an underlying NSURLSession first establishes a connection to a remote server that uses SSL or TLS,
 to allow your app to verify the server’s certificate chain. The challenge parameter is already tested for `NSURLAuthenticationMethodServerTrust`.
 
 The implementation must call `completionHandler` with an appropriate result of the verification.
 */
- (void) validateSslForSession:(nonnull NSURLSession *)session
					 challenge:(nonnull NSURLAuthenticationChallenge *)challenge
			 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler;

@end
