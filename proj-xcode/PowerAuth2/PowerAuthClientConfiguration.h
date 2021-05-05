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
 The `PowerAuthClientSslValidationStrategy` protocol defines interface for custom TLS connection validation.
 */
@protocol PowerAuthClientSslValidationStrategy <NSObject>

/**
 The method is called when an underlying NSURLSession first establishes a connection to a remote server that uses SSL or TLS,
 to allow your app to verify the server’s certificate chain. The challenge parameter is already tested for `NSURLAuthenticationMethodServerTrust`.
 
 The implementation must call `completionHandler` with an appropriate result of the verification.
 */
- (void) validateSslForSession:(nonnull NSURLSession *)session
					 challenge:(nonnull NSURLAuthenticationChallenge *)challenge
			 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler;

@end

/**
 The `PowerAuthHttpRequestInterceptor` protocol defines interface for modifying HTTP requests
 before their execution.
 
 WARNING
 
 This protocol allows you to tweak the requests created in the PowerAuthSDK, but
 also gives you an opportunity to break the things. So, rather than create your own interceptor,
 try to contact us and describe what's your problem with the networking in the PowerAuth SDK.
 
 Also note, that this interface may change in the future. We can guarantee the API stability of
 public classes implementing this interface, but not the stability of interface itself.
 */
@protocol PowerAuthHttpRequestInterceptor <NSObject>

/**
 Method is called by the internal HTTP client, before the request is executed.
 The implementation must count with that method is called from other than UI thread.
 
 @param request URL request to be modified.
 */
- (void) processRequest:(nonnull NSMutableURLRequest*)request;

@end


/**
 Class that is used to provide default (shared) RESTful API client configuration.
 */
@interface PowerAuthClientConfiguration : NSObject<NSCopying>

/**
 Property that specifies the default HTTP client request timeout. The default value is 20.0 (seconds).
 */
@property (nonatomic, assign) NSTimeInterval defaultRequestTimeout;

/**
 Property that specifies the SSL validation strategy applied by the client. The default value is the default NSURLSession behavior.
 */
@property (nonatomic, strong, nullable) id<PowerAuthClientSslValidationStrategy> sslValidationStrategy;

/**
 Property that specifies the list of request interceptors used by the client before the request is executed. The default value is nil.
 */
@property (nonatomic, strong, nullable) NSArray<id<PowerAuthHttpRequestInterceptor>>* requestInterceptors;

/**
 Return the shared in stance of a client configuration object.
 
 @return Shared instance of a client configuration.
 */
+ (nonnull instancetype) sharedInstance;

@end
