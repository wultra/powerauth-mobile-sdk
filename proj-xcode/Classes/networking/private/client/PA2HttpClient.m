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
#import "PA2Log.h"

@implementation PA2HttpClient
{
	dispatch_queue_t _completionQueue;
}

/**
 Returns a shared, concurrent queue.
 */
static NSOperationQueue * _GetSharedConcurrentQueue()
{
	static dispatch_once_t onceToken;
	static NSOperationQueue * s_queue;
	dispatch_once(&onceToken, ^{
		s_queue = [[NSOperationQueue alloc] init];
		s_queue.name = @"PA2HttpClient_Concurrent";
	});
	return s_queue;
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
		
		// Prepare serial queue
		_serialQueue = [[NSOperationQueue alloc] init];
		_serialQueue.maxConcurrentOperationCount = 1;
		_serialQueue.name = @"PA2HttpClient_Serial";
		
		// Prepare NSURLSession's configuration (the copy is probably not required, but unfortunately,
		// the documentation is not very specific, whether the new instance of ephemeral config is returned)
		NSURLSessionConfiguration *sessionConfiguration = [[NSURLSessionConfiguration ephemeralSessionConfiguration] copy];
		sessionConfiguration.URLCache = nil;
		sessionConfiguration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
		sessionConfiguration.timeoutIntervalForRequest = configuration.defaultRequestTimeout;
		
		// And finally, construct the session. We can use the shared concurrent queue for
		// scheduling session's delegate messages.
		_session = [NSURLSession sessionWithConfiguration:sessionConfiguration
												 delegate:self
											delegateQueue:_GetSharedConcurrentQueue()];
	}
	return self;
}

- (void) dealloc
{
	[_session finishTasksAndInvalidate];
}

- (NSOperationQueue*) concurrentQueue
{
	return _GetSharedConcurrentQueue();
}

#pragma mark - Debug Log

#ifdef DEBUG
// Functions implementing request-response logging.
static void _LogHttpRequest(PA2RestApiEndpoint * endpoint, NSURLRequest * request)
{
	if (PA2LogIsEnabled()) {
		// Warn if communication is not encrypted.
		if ([request.URL.scheme isEqualToString:@"http"]) {
			static BOOL s_warning = YES;
			if (s_warning) {
				PA2Log(@"Warning: Using HTTP for communication may create a serious security issue! Use HTTPS in production.");
				s_warning = NO;
			}
		}
		
		BOOL signature = endpoint.authUriId != nil;
		BOOL encrypted = endpoint.encryptor != PA2EncryptorId_None;
		
		NSString * signedEncrypted = (signature ? (encrypted ? @" (sig+enc)" : @" (sig)") : (encrypted ? @" (enc)" : @""));
		NSString * msg = [NSString stringWithFormat:@"HTTP %@ request%@: → %@", request.HTTPMethod, signedEncrypted, request.URL.absoluteString];
		if (PA2LogIsVerbose()) {
			msg = [msg stringByAppendingFormat:@"\n+ Headers: %@", request.allHTTPHeaderFields];
			if (!encrypted) {
				NSString * jsonBody = request.HTTPBody.length > 0 ? [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding] : @"<empty>";
				msg = [msg stringByAppendingFormat:@"\n+ Body: %@", jsonBody];
			}
		}
		PA2Log(@"%@", msg);
	}
}

static void _LogHttpResponse(PA2RestApiEndpoint * endpoint, NSHTTPURLResponse * response, NSData * data, NSError * error)
{
	if (PA2LogIsEnabled()) {
		BOOL encrypted = endpoint.encryptor != PA2EncryptorId_None;
		NSNumber * statusCode = @(response.statusCode);
		NSString * msg = [NSString stringWithFormat:@"HTTP %@ reponse %@: ← %@", endpoint.method, statusCode, response.URL.absoluteString];
		if (PA2LogIsVerbose()) {
			msg = [msg stringByAppendingFormat:@"\n+ Headers: %@", response.allHeaderFields];
			if (!encrypted) {
				NSString * jsonData = data.length > 0 ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"<empty>";
				msg = [msg stringByAppendingFormat:@"\n+ Body: %@", jsonData];
			}
		}
		if (error) {
			msg = [msg stringByAppendingFormat:@"\n+ Error: %@", error];
		}
		PA2Log(@"%@", msg);
	}
}
#else
// Turn-Off request-response logging
#define _LogHttpRequest(endpoint, request)
#define _LogHttpResponse(endpoint, response, data, error)
#endif // DEBUG


#pragma mark - POST

- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
{
	return [self postObject:object to:endpoint auth:nil completion:completion cancel:nil];
}

- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
					   auth:(PowerAuthAuthentication*)authentication
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
{
	return [self postObject:object to:endpoint auth:authentication completion:completion cancel:nil];
}

- (NSOperation*) postObject:(id<PA2Encodable>)object
						 to:(PA2RestApiEndpoint*)endpoint
					   auth:(PowerAuthAuthentication*)authentication
				 completion:(void(^)(PA2RestResponseStatus status, id<PA2Decodable> response, NSError * error))completion
					 cancel:(void(^)(void))customCancelBlock
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
		// Process all request interceptors
		[_configuration.requestInterceptors enumerateObjectsUsingBlock:^(id<PA2HttpRequestInterceptor> interceptor, NSUInteger idx, BOOL * stop) {
			[interceptor processRequest:urlRequest];
		}];
		// Log request
		_LogHttpRequest(endpoint, urlRequest);
		// Construct & return data task.
		NSURLSessionDataTask * task = [_session dataTaskWithRequest:urlRequest completionHandler:^(NSData * data, NSURLResponse * urlResponse, NSError * error) {
			// DataTask completion
			id<PA2Decodable> object;
			if (!error) {
				object = [request buildResponseObjectFrom:data httpResponse:(NSHTTPURLResponse*)urlResponse error:&error];
			} else {
				object = nil;
			}
			// Log response
			_LogHttpResponse(endpoint, (NSHTTPURLResponse*)urlResponse, data, error);
			// Complete operation
			[op completeWithResult:object error:error];
		}];
		[task resume];
		return task;
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
		if (customCancelBlock) {
			customCancelBlock();
		}
	};
	
	// Finally, add operation to the right queue
	NSOperationQueue * queue = endpoint.isSerialized ? _serialQueue : _GetSharedConcurrentQueue();
	[queue addOperation:op];
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
