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

#import "PA2HttpClient.h"
#import "PA2AsyncOperation.h"
#import "PA2PrivateMacros.h"

@implementation PA2HttpClient
{
	dispatch_queue_t _completionQueue;
	dispatch_queue_t _dispatchQueue;
}

- (instancetype) initWithConfiguration:(PA2ClientConfiguration*)configuration
					   completionQueue:(dispatch_queue_t)completionQueue
							   baseUrl:(NSString*)baseUrl
								helper:(id<PA2PrivateCryptoHelper>)helper
{
	self = [super init];
	if (self) {
		_configuration = configuration;
		_completionQueue = completionQueue;
		_cryptoHelper = helper;

		// Prepare baseUrl (without the last separator)
		if ([baseUrl hasSuffix:@"/"]) {
			_baseUrl = [baseUrl substringToIndex:baseUrl.length - 1];
		} else {
			_baseUrl = baseUrl;
		}
		
		// Prepare queues.
		// Note that dispatch queue is serial, but NSOPerationQueue is concurrent (by default)
		_dispatchQueue = dispatch_queue_create("PA2HttpClient", DISPATCH_QUEUE_SERIAL);
		_operationQueue = [[NSOperationQueue alloc] init];
		_operationQueue.underlyingQueue = _dispatchQueue;
		
		// Prepare NSURLSession's configuration
		NSURLSessionConfiguration *sessionConfiguration = [[NSURLSessionConfiguration ephemeralSessionConfiguration] copy];
		sessionConfiguration.URLCache = nil;
		sessionConfiguration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
		sessionConfiguration.timeoutIntervalForRequest = configuration.defaultRequestTimeout;
		
		// And finally, construct the session
		_session = [NSURLSession sessionWithConfiguration:sessionConfiguration delegate:self delegateQueue:_operationQueue];
	}
	return self;
}

- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
{
	return [self postObject:object to:endpoint auth:nil completion:completion];
}


- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
					   auth:(PowerAuthAuthentication*)authentication
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
{
	// Construct asynchronous operation & associated request
	PA2AsyncOperation * op = [[PA2AsyncOperation alloc] initWithReportQueue:_completionQueue];
	PA2HttpRequest * request = [[PA2HttpRequest alloc] initWithEndpoint:endpoint
														  requestObject:object
														 authentication:authentication];
	// Setup execution block
	op.executionBlock = ^id(PA2AsyncOperation *op) {
		// Now it's time to construct HTTP request.
		NSError * error = nil;
		NSMutableURLRequest * urlRequest = [request buildRequestWithHelper:_cryptoHelper baseUrl:_baseUrl error:&error];
		if (error) {
			[op completeWithResult:nil error:error];
			return nil;
		}
		// Construct & return data task.
		return [_session dataTaskWithRequest:urlRequest completionHandler:^(NSData * data, NSURLResponse * response, NSError * error) {
			// DataTask completion
			id<PA2Decodable> object;
			if (!error) {
				object = [request buildResponseObjectFrom:data httpResponse:(NSHTTPURLResponse*)response error:&error];
			} else {
				object = nil;
			}
			[op completeWithResult:object error:error];
		}];
	};
	// Reporting block
	op.reportBlock = ^(PA2AsyncOperation *op) {
		id<PA2Decodable> object = op.operationResult;
		NSError * error = op.operationError;
		PA2RestResponseStatus status = error == nil ? PA2RestResponseStatus_OK : PA2RestResponseStatus_ERROR;
		completion(status, object, error);
	};
	// Setup cancellation block
	op.cancelBlock = ^(PA2AsyncOperation *op, id task) {
		[PA2ObjectAs(task, NSURLSessionDataTask) cancel];
	};
	
	// Finally, add operation to the queue
	[_operationQueue addOperation:op];
	return op;
}


#pragma mark - NSURLSessionDelegate methods

- (void) URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler
{
	if (_configuration.sslValidationStrategy && [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
		[_configuration.sslValidationStrategy validateSslForSession:session challenge:challenge completionHandler:completionHandler];
	} else {
		completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
	}
}

@end
