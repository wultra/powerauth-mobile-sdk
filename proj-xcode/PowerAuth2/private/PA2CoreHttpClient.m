/*
 * Copyright 2025 Wultra s.r.o.
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

#import "PA2CoreHttpClient.h"
#import "PA2CompositeTask.h"
#import "PA2CoreTaskWrapper.h"
#import "PA2AsyncOperation.h"
#import "PA2PrivateMacros.h"
#import "PA2ErrorResponse+Decodable.h"

#import <PowerAuth2/PowerAuthLog.h>

@import PowerAuthCore;

#pragma mark - Forward declarations

#if defined(DEBUG)
    // Failure simulator
    static NSError * _GetSimulatedRequestFailure(NSString * basePath, NSString * relativePath);
    static NSArray * _GetSimulatedResponseFailure(NSString * basePath, NSString * relativePath);
    static id _GetNullableObjectFromArray(NSArray * array, NSUInteger index);
    // LOG
    static void _LogHttpRequest(PowerAuthCoreRequest * coreRequest, NSURLRequest * request);
    static void _LogHttpResponse(PowerAuthCoreRequest * coreRequest, NSHTTPURLResponse * response, NSData * data, NSError * error);
#else
    // Turn-Off request-response logging
    #define _LogHttpRequest(coreRequest, request)
    #define _LogHttpResponse(coreRequest, response, data, error)
#endif // DEBUG

#pragma mark - Client implementation

/// Returns a shared, concurrent queue.
static NSOperationQueue * _GetSharedConcurrentQueue(void)
{
    static dispatch_once_t onceToken;
    static NSOperationQueue * s_queue;
    dispatch_once(&onceToken, ^{
        s_queue = [[NSOperationQueue alloc] init];
        s_queue.name = @"PA2CoreHttpClient_Concurrent";
    });
    return s_queue;
}

@implementation PA2CoreHttpClient
{
    PowerAuthClientConfiguration* _configuration;
    dispatch_queue_t _completionQueue;
    NSString * _baseUrl;
}

- (nonnull instancetype) initWithConfiguration:(nonnull PowerAuthClientConfiguration*)configuration
                              sessionInterface:(nonnull id<PA2SessionInterface>)sessionInterface
                               completionQueue:(nonnull dispatch_queue_t)queue
                                       baseUrl:(nonnull NSString*)baseUrl
{
    self = [super init];
    if (self) {
        _configuration = configuration;
        _sessionInterface = sessionInterface;
        _completionQueue = queue;

        // Prepare baseUrl (without the last separator)
        if ([baseUrl hasSuffix:@"/"]) {
            _baseUrl = [baseUrl substringToIndex:baseUrl.length - 1];
        } else {
            _baseUrl = baseUrl;
        }
        
        // Prepare serial queue
        _serialQueue = [[NSOperationQueue alloc] init];
        _serialQueue.maxConcurrentOperationCount = 1;
        _serialQueue.name = @"PA2CoreHttpClient_Serial";
        
        // Prepare NSURLSession's configuration (the copy is probably not required, but unfortunately,
        // the documentation is not very specific, whether the new instance of ephemeral config is returned)
        NSURLSessionConfiguration *sessionConfiguration = [[NSURLSessionConfiguration ephemeralSessionConfiguration] copy];
        sessionConfiguration.URLCache = nil;
        sessionConfiguration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        sessionConfiguration.timeoutIntervalForRequest = configuration.defaultRequestTimeout;
        
        // And finally, construct the session. We can use the shared concurrent queue for
        // scheduling session's delegate messages.
        _urlSession = [NSURLSession sessionWithConfiguration:sessionConfiguration
                                                    delegate:self
                                               delegateQueue:_GetSharedConcurrentQueue()];
    }
    return self;
}

- (void) dealloc
{
    [_urlSession finishTasksAndInvalidate];
}

- (NSOperationQueue*) concurrentQueue
{
    return _GetSharedConcurrentQueue();
}

- (id<PowerAuthOperationTask>) postCoreRequest:(PowerAuthCoreRequest*)request
                                    completion:(void(^)(PowerAuthCoreRequest * request, id response, NSError * error))completion
{
    PA2TimeSynchronizationService * timeService = [_sessionInterface timeSynchronizationService];
    PA2KeystoreService * keystoreService = [_sessionInterface keystoreService];
    PowerAuthCoreEncryptorScope encryptorScope = request.encryptorScope;

    BOOL requireSynchronizedTime = request.isRequireSynchronizedTime && ![timeService isTimeSynchronized];
    BOOL requireEncryptionKey = encryptorScope != PowerAuthCoreEncryptorScope_None && ![keystoreService hasKeyForEncryptorScope:encryptorScope];
    if (requireSynchronizedTime || requireEncryptionKey) {
        // Endpoint require encryption key or time is not synchronized yet. We have to create a composite task that handle multiple
        // requests before an actual request is executed.
        PA2CompositeTask * compositeTask = [[PA2CompositeTask alloc] initWithCancelBlock:^{
            [self setCoreRequestFinished:request isFailed:NO urlTask:nil];
        }];
        // Prepare common completion block with the composite task.
        void (^compositeCompletion)(PowerAuthCoreRequest *, id, NSError *) = ^(PowerAuthCoreRequest * request, id response, NSError *error) {
            // At first, dispatch the result to the dedicated queue.
            dispatch_async(_completionQueue, ^{
                // Make sure the core request is set as failed
                if (error) {
                    [self setCoreRequestFinished:request isFailed:YES urlTask:nil];
                }
                // Set composite operation as completed. The message returns YES if composite task was not completed or canceled before.
                // If so, then simply call the completion block.
                if ([compositeTask setCompleted]) {
                    completion(request, response, error);
                }
            });
        };
        // Now determine what type of task should be executed before an actual task
        if (requireEncryptionKey) {
            // Acquire temporary encryption key. This also synchronizes time as a side effect.
            id<PowerAuthOperationTask> getKeyTask = [keystoreService createKeyForEncryptorScope:encryptorScope callback:^(NSError * _Nullable error) {
                if (!error) {
                    // The temporary encryption key has been successfully obtained, we can continue with the actual request.
                    NSOperation* actualOperation = [self executeCoreRequest:request completion:compositeCompletion];
                    [compositeTask replaceOperationTask:actualOperation];
                } else {
                    // Report error to composite completion.
                    compositeCompletion(request, nil, error);
                }
            } callbackQueue:nil];
            [compositeTask replaceOperationTask:getKeyTask];
        } else {
            // start the time synchronization
            id<PowerAuthOperationTask> synchronizationTask = [timeService synchronizeTimeWithCallback:^(NSError * error) {
                if (!error) {
                    // The time has been successfully synchronized, we can continue with the actual request.
                    NSOperation* actualOperation = [self executeCoreRequest:request completion:compositeCompletion];
                    [compositeTask replaceOperationTask:actualOperation];
                } else {
                    // Report error to composite completion.
                    compositeCompletion(request, nil, error);
                }
            } callbackQueue:_completionQueue];
            [compositeTask replaceOperationTask:synchronizationTask];
        }
        return compositeTask;
    }
    // Endpoint doesn't require time synchronization or encryption, or time is synchronized and key is available.
    return [self executeCoreRequest:request completion:completion];
}

- (NSOperation*) executeCoreRequest:(PowerAuthCoreRequest*)request
                         completion:(void(^)(PowerAuthCoreRequest * request, id response, NSError * error))completion
{
    // Construct asynchronous operation & associated request
    PA2AsyncOperation * op = [[PA2AsyncOperation alloc] initWithReportQueue:_completionQueue];
    // Setup execution block
    op.executionBlock = ^id(PA2AsyncOperation *op) {
        // Now it's time to construct HTTP request.
        NSError * error = nil;
        // Build URL request from core request
        NSMutableURLRequest * urlRequest = [self buildUrlRequest:request error:&error];
        if (error) {
            [op completeWithResult:nil error:error];
            return nil;
        }
        // Adjust user agent, if required
        if (_configuration.userAgent) {
            [urlRequest addValue:_configuration.userAgent forHTTPHeaderField:@"User-Agent"];
        }
        // Process all request interceptors
        [_configuration.requestInterceptors enumerateObjectsUsingBlock:^(id<PowerAuthHttpRequestInterceptor> interceptor, NSUInteger idx, BOOL * stop) {
            [interceptor processRequest:urlRequest];
        }];
        // Log request
        _LogHttpRequest(request, urlRequest);
        
#if defined(DEBUG)
        // Failure simulator
        error = _GetSimulatedRequestFailure(_baseUrl, request.relativePath);
        if (error) {
            _LogHttpResponse(request, nil, nil, error);
            [op completeWithResult:nil error:error];
            return nil;
        }
#endif
        // Construct & return data task.
        NSURLSessionDataTask * task = [_urlSession dataTaskWithRequest:urlRequest completionHandler:^(NSData * data, NSURLResponse * urlResponse, NSError * error) {
#if defined(DEBUG)
            // Failure simulator
            NSArray * simulatedResponseFailure = _GetSimulatedResponseFailure(_baseUrl, request.relativePath);
            if (simulatedResponseFailure) {
                urlResponse = _GetNullableObjectFromArray(simulatedResponseFailure, 0);
                data        = _GetNullableObjectFromArray(simulatedResponseFailure, 1);
                error       = _GetNullableObjectFromArray(simulatedResponseFailure, 2);
            }
#endif // DEBUG
            // DataTask completion
            id object;
            if (!error) {
                object = [self buildResponse:request responseData:data response:(NSHTTPURLResponse*)urlResponse error:&error];
            } else {
                // Network, or other error. Report this immediately to C++ layer.
                [self setCoreRequestFinished:request isFailed:YES urlTask:nil];
                object = nil;
            }
            // Log response
            _LogHttpResponse(request, (NSHTTPURLResponse*)urlResponse, data, error);
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
        // Make sure the core request is set as failed before we call the completion.
        if (error) {
            [self setCoreRequestFinished:request isFailed:YES urlTask:nil];
        }
        completion(request, object, error);
    };
    // Setup cancellation block
    op.cancelBlock = ^(PA2AsyncOperation *op, id task) {
        [self setCoreRequestFinished:request isFailed:NO urlTask:PA2ObjectAs(task, NSURLSessionDataTask)];
    };
    // Finally, add operation to the right queue
    if (request.isRequireSerialQueue) {
        // The request must be serialized in serial queue.
        [_sessionInterface executeOutsideOfTask:^{
            [_sessionInterface addOperation:op toSharedQueue:_serialQueue];
        } queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)];
    } else {
        // The concurrent queue can be used
        [_GetSharedConcurrentQueue() addOperation:op];
    }
    return op;
}

- (id<PowerAuthOperationTask>) postCoreTask:(PowerAuthCoreTask *)task
                                 completion:(void (^)(PowerAuthCoreTask *, id, NSError *))completion
{
    return [[[PA2CoreTaskWrapper alloc] initWithCoreTask:task
                                              httpClient:self
                                              completion:completion] processNext];
}

- (NSMutableURLRequest*) buildUrlRequest:(PowerAuthCoreRequest*)coreRequest error:(NSError**)error
{
    NSError * localError = nil;
    __block BOOL processed = NO;
    [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        processed = YES;
        return [coreRequest prepareRequest:error];
    } error:&localError];
    if (localError) {
        if (!processed) {
            // We never entered to the request preparation block. In this case, we have to try to cancel the core request
            // to notify core layer about this failure.
            [self setCoreRequestFinished:coreRequest isFailed:YES urlTask:nil];
        }
        return nil;
    }
    NSData* requestBody = coreRequest.requestBody;
    if (!requestBody) {
        PA2WrapError(coreRequest.failure, error);
        return nil;
    }
    NSArray<PowerAuthCoreHttpHeader*>* requestHeaders = coreRequest.requestHeaders;
    if (!requestHeaders) {
        PA2WrapError(coreRequest.failure, error);
        return nil;
    }

    // Build full URL & request object
    NSURL* url = [NSURL URLWithString:[_baseUrl stringByAppendingString:coreRequest.relativePath]];
    NSMutableURLRequest* request = [[NSMutableURLRequest alloc] initWithURL:url];
    if (!request) {
        PA2SetError(error, PowerAuthErrorCode_NetworkError, @"Failed to build URLRequest");
        return nil;
    }
    request.HTTPMethod = coreRequest.httpMethod;
    request.HTTPBody = coreRequest.requestBody;
    [requestHeaders enumerateObjectsUsingBlock:^(PowerAuthCoreHttpHeader * header, NSUInteger idx, BOOL *stop) {
        [request addValue:header.headerValue forHTTPHeaderField:header.headerName];
    }];
    return request;
}

/// Build success or failure response from the received data.
/// - Parameters:
///   - coreRequest: Core request.
///   - responseData: Received response data.
///   - httpResponse: HTTP response object
///   - error: Pointer to output error object.
/// - Returns: Response object (if present).
- (id) buildResponse:(PowerAuthCoreRequest*)coreRequest responseData:(NSData*)responseData response:(NSHTTPURLResponse*)httpResponse error:(NSError**)error
{
    if (httpResponse.statusCode == 200) {
        // Acquire lock before the
        __block BOOL processed = NO;
        [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
            processed = YES;
            return [coreRequest processResponse:responseData error:error];
        } error:error];
        if (*error) {
            if (!processed) {
                // We never entered to the response processing. In this case, we have to try to
                // set the core request as failed to notify core layer about this.
                [self setCoreRequestFinished:coreRequest isFailed:YES urlTask:nil];
            }
            return nil;
        }
        // success, note that response object may be nil
        return coreRequest.responseObject;
    }
    // Notify C++ layer about this failure.
    [self setCoreRequestFinished:coreRequest isFailed:YES urlTask:nil];
    // build error
    *error = [self buildErrorForData:responseData httpResponse:httpResponse];
    return nil;
}


/// Private function builds `NSError` object from available data & HTTP response.
/// The returned error has "domain" equal to `PA2ErrorDomain` and contains additional
/// information bundled in the "userInfo" dictionary.
/// - Parameters:
///   - data: Body with error response
///   - httpResponse: HTTP response object
/// - Returns: NSError created from received data.
- (NSError*) buildErrorForData:(NSData*)data
                  httpResponse:(NSHTTPURLResponse*)httpResponse
{
    NSError * localError = nil;
    // Try to deserialize JSON
    id JSONData = [NSJSONSerialization JSONObjectWithData:data options:0 error:&localError];
    NSDictionary * responseDictionary = data ? PA2ObjectAs(JSONData, NSDictionary) : nil;
    // Create PA2ErrorResponse object.
    // If there was an error with JSON decoding, then use nil for object constuction.
    PowerAuthRestApiErrorResponse * httpResponseObject = [[PowerAuthRestApiErrorResponse alloc] initWithDictionary:localError ? nil : responseDictionary];
    // Keep status code in response object
    httpResponseObject.httpStatusCode = httpResponse.statusCode;
    
    NSDictionary * additionalInfo =
    @{
        PowerAuthErrorDomain:                   httpResponseObject,
        PowerAuthErrorInfoKey_AdditionalInfo:   responseDictionary ? responseDictionary : @{},
        PowerAuthErrorInfoKey_ResponseData:     data ? data : [NSData data],
        NSLocalizedDescriptionKey:              PA2MakeDefaultErrorDescription(PowerAuthErrorCode_NetworkError, nil)
    };
    return [NSError errorWithDomain:PowerAuthErrorDomain code:PowerAuthErrorCode_NetworkError userInfo:additionalInfo];
}

- (void) setCoreRequestFinished:(PowerAuthCoreRequest*)request
                       isFailed:(BOOL)isFailed
                        urlTask:(NSURLSessionDataTask*)task
{
    [task cancel];
    if (request && !request.isDone) {
        // acquire write task in case the cancel cause internal state change
        [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * _Nonnull session, NSError * _Nonnull __autoreleasing * _Nullable error) {
            if (isFailed) {
                [request setFailed];
            } else {
                [request cancel];
            }
            return YES;
        } error:nil];
    }
}

@end // @implementation PA2CoreHttpClient


#pragma mark - Debug Log

#if defined(DEBUG)
// Functions implementing request-response logging.
static void _LogHttpRequest(PowerAuthCoreRequest * coreRequest, NSURLRequest * request)
{
    if (PowerAuthLogIsEnabled()) {
        // Warn if communication is not encrypted.
        if ([request.URL.scheme isEqualToString:@"http"]) {
            static BOOL s_warning = YES;
            if (s_warning) {
                PowerAuthLog(@"Warning: Using HTTP for communication may create a serious security issue! Use HTTPS in production.");
                s_warning = NO;
            }
        }
        
        BOOL authCode = coreRequest.isAuthenticated;
        BOOL encrypted = coreRequest.encryptorScope != PowerAuthCoreEncryptorScope_None;
        
        NSString * signedEncrypted = (authCode ? (encrypted ? @" (auth+enc)" : @" (auth)") : (encrypted ? @" (enc)" : @""));
        NSString * msg = [NSString stringWithFormat:@"HTTP %@ request%@: → %@", request.HTTPMethod, signedEncrypted, request.URL.absoluteString];
        if (PowerAuthLogIsVerbose()) {
            msg = [msg stringByAppendingFormat:@"\n+ Headers: %@", request.allHTTPHeaderFields];
            if (!encrypted) {
                NSString * jsonBody = request.HTTPBody.length > 0 ? [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding] : @"<empty>";
                msg = [msg stringByAppendingFormat:@"\n+ Body: %@", jsonBody];
            }
        }
        PowerAuthLog(@"%@", msg);
    }
}

static void _LogHttpResponse(PowerAuthCoreRequest * coreRequest, NSHTTPURLResponse * response, NSData * data, NSError * error)
{
    if (PowerAuthLogIsEnabled()) {
        BOOL encrypted = coreRequest.encryptorScope != PowerAuthCoreEncryptorScope_None;
        NSNumber * statusCode = @(response.statusCode);
        NSString * msg = [NSString stringWithFormat:@"HTTP %@ response %@: ← %@", coreRequest.httpMethod, statusCode, response.URL.absoluteString];
        if (PowerAuthLogIsVerbose()) {
            msg = [msg stringByAppendingFormat:@"\n+ Headers: %@", response.allHeaderFields];
            if (!encrypted) {
                NSString * jsonData = data.length > 0 ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"<empty>";
                msg = [msg stringByAppendingFormat:@"\n+ Body: %@", jsonData];
            }
        }
        if (error) {
            msg = [msg stringByAppendingFormat:@"\n+ Error: %@", error];
        }
        PowerAuthLog(@"%@", msg);
    }
}
#endif // DEBUG

#pragma mark - Debug Failure Simulator

#if defined(DEBUG)
@implementation PA2CoreHttpClient (FailureSimulator)

#define KEY_RESP @"response"
#define KEY_SEND @"ioSend"
#define KEY_RECV @"ioRecv"

static NSMutableDictionary * _GetFailureData(void)
{
    static dispatch_once_t onceToken;
    static NSMutableDictionary * s_Failures;
    dispatch_once(&onceToken, ^{
        s_Failures = [NSMutableDictionary dictionary];
        s_Failures[KEY_RESP] = [NSMutableDictionary dictionary];
        s_Failures[KEY_SEND] = [NSMutableDictionary dictionary];
        s_Failures[KEY_RECV] = [NSMutableSet set];
    });
    return s_Failures;
}

static NSString * _ProcessRelativePath(NSString * relativePath)
{
    return relativePath ? relativePath : @"*";
}

+ (void) setNextResponseFailure:(nullable NSString*)relativePath
                     statusCode:(NSInteger)statusCode
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        relativePath = _ProcessRelativePath(relativePath);
        NSMutableDictionary * response = failures[KEY_RESP];
        response[relativePath] = @(statusCode);
        PowerAuthLog(@"!!! Next HTTP response will fail on %@: %@", @(statusCode), relativePath);
    }
}

+ (void) setNextRequestNetworkFailureOnSend:(nullable NSString*)relativePath
                                repeatCount:(NSInteger)count
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        relativePath = _ProcessRelativePath(relativePath);
        NSMutableDictionary * onSend = failures[KEY_SEND];
        onSend[relativePath] = @(count);
        PowerAuthLog(@"!!! Next HTTP request will fail on send: %@", relativePath);
    }
}

+ (void) setNextRequestNetworkFailureOnReceive:(nullable NSString*)relativePath
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        relativePath = _ProcessRelativePath(relativePath);
        NSMutableSet * onRecv = failures[KEY_RECV];
        [onRecv addObject:relativePath];
        PowerAuthLog(@"!!! Next HTTP request will fail on receive: %@", relativePath);
    }
}

+ (void) clearAllFailureHooks
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        NSMutableDictionary * response = failures[KEY_RESP];
        NSMutableDictionary * onSend   = failures[KEY_SEND];
        NSMutableSet *        onRecv   = failures[KEY_RECV];
        if (onSend.count || onRecv.count || response.count) {
            // Do not spoil log in case there's no hook
            PowerAuthLog(@"!!! Removing all simulated HTTP failure hooks");
            [response removeAllObjects];
            [onRecv removeAllObjects];
            [onSend removeAllObjects];
        }
    }
}

static NSError * _GetSimulatedRequestFailure(NSString * basePath, NSString * relativePath)
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        NSMutableDictionary * onSend = failures[KEY_SEND];
        if ([onSend count]) {
            NSString * pathToMatch = relativePath;
            NSNumber * count = onSend[pathToMatch];
            if (!count) {
                pathToMatch = @"*";
                count = onSend[pathToMatch];
            }
            if (count) {
                NSInteger remaining = count.unsignedIntegerValue;
                if (remaining > 1) {
                    onSend[pathToMatch] = @(remaining - 1);
                } else {
                    [onSend removeObjectForKey:pathToMatch];
                }
                
                NSString * urlString = [basePath stringByAppendingString:relativePath];
                return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost userInfo:@{
                    NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Simulated error on data send: %@", urlString]
                }];
            }
        }
        return nil;
    }
}

static NSArray * _GetSimulatedResponseFailure(NSString * basePath, NSString * relativePath)
{
    NSMutableDictionary * failures = _GetFailureData();
    @synchronized (failures) {
        NSMutableDictionary * response = failures[KEY_RESP];
        NSMutableSet        * onRecv   = failures[KEY_RECV];
        
        NSString * pathToMatch;
        // Receive error
        if ([onRecv count]) {
            pathToMatch = relativePath;
            BOOL matched = [onRecv containsObject:pathToMatch];
            if (!matched) {
                pathToMatch = @"*";
                matched = [onRecv containsObject:pathToMatch];
            }
            if (matched) {
                [onRecv removeObject:pathToMatch];
                NSString * urlString = [basePath stringByAppendingString:relativePath];
                return @[
                    [NSNull null],
                    [NSNull null],
                    [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNetworkConnectionLost userInfo:@{
                        NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Simulated error on data receive: %@", urlString]
                    }]
                ];
            }
        }
        // Response error
        if ([response count]) {
            pathToMatch = relativePath;
            NSNumber * status = response[pathToMatch];
            if (!status) {
                pathToMatch = @"*";
                status = response[pathToMatch];
            }
            if (status) {
                [response removeObjectForKey:pathToMatch];
                NSURL* url = [NSURL URLWithString:[basePath stringByAppendingString:relativePath]];
                return @[
                    [[NSHTTPURLResponse alloc] initWithURL:url statusCode:status.integerValue HTTPVersion:nil headerFields:nil],
                    [@"{\"status\": \"ERROR\",\"responseObject\":{\"code\": \"ERR_SIMULATED_FAILURE\",\"message\": \"This is fine 🐶\"}}" dataUsingEncoding:NSUTF8StringEncoding],
                    [NSNull null]
                ];
            }
        }
        return nil;
    }
}

static id _GetNullableObjectFromArray(NSArray * array, NSUInteger index)
{
    id obj = [array objectAtIndex:index];
    if ([obj isKindOfClass:[NSNull class]]) {
        return nil;
    }
    return obj;
}

@end // @implementation PA2CoreHttpClient (FailureSimulator)

#endif // DEBUG
