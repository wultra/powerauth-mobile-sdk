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

@import PowerAuthCore;

@implementation PA2CoreHttpClient
{
    PowerAuthClientConfiguration* _configuration;
    id<PA2SessionInterface> _sessionInterface;
    dispatch_queue_t _completionQueue;
    NSString * _baseUrl;
    
    PowerAuthCoreTimeService * _timeService;
    PowerAuthCoreEncryptorFactory * _encryptorFactory;
}

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

- (nonnull instancetype) initWithConfiguration:(nonnull PowerAuthClientConfiguration*)configuration
                          coreSessionInterface:(nonnull id<PA2SessionInterface>)sessionInterface
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
        _session = [NSURLSession sessionWithConfiguration:sessionConfiguration
                                                 delegate:self
                                            delegateQueue:_GetSharedConcurrentQueue()];
        
        [_sessionInterface readVoidTaskWithSession:^(PowerAuthCoreSession * _Nonnull session) {
            
        }];
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

- (nonnull id<PowerAuthOperationTask>) postCoreRequest:(nonnull PowerAuthCoreRequest*)request
                                            completion:(void(^)(PowerAuthRestApiResponseStatus status, id response, NSError * error))completion
{
    PowerAuthCoreEncryptorScope encryptorScope = request.encryptorScope;
    BOOL requireSynchronizedTime = request.isRequireSynchronizedTime && ![_timeService isTimeSynchronized];
    BOOL requireEncryptionKey = encryptorScope != PowerAuthCoreEncryptorScope_None && ![_encryptorFactory hasTemporaryKeyForScope:encryptorScope];
    if (requireSynchronizedTime || requireEncryptionKey) {
        // Endpoint require encryption key or time is not synchronized yet. We have to create a composite task that handle multiple
        // requests before an actual request is executed.
        PA2CompositeTask * compositeTask = [[PA2CompositeTask alloc] initWithCancelBlock:^{
            [request cancel];
        }];
        // Prepare common completion block with the composite task.
        void (^compositeCompletion)(PowerAuthRestApiResponseStatus, id, NSError *) = ^(PowerAuthRestApiResponseStatus status, id response, NSError *error) {
            // At first, dispatch the result to the dedicated queue.
            dispatch_async(_completionQueue, ^{
                // Set composite operation as completed. The message returns YES if composite task was not completed or canceled before.
                // If so, then simply call the completion block.
                if ([compositeTask setCompleted]) {
                    completion(status, response, error);
                }
            });
        };

    }
}

@end
