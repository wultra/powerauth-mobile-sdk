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

#import "PA2CoreTaskWrapper.h"
#import "PA2PrivateMacros.h"
#import "PA2CoreHttpClient.h"
#import "PA2SessionInterface.h"

@implementation PA2CoreTaskWrapper
{
    PowerAuthCoreTask * _task;
    PA2CoreHttpClient * _client;
    void(^_completion)(PowerAuthCoreTask*, id, NSError *);
    
    id<PowerAuthOperationTask> _current_async_operation;
}
- (id) initWithCoreTask:(nonnull PowerAuthCoreTask*)task
             httpClient:(nonnull PA2CoreHttpClient*)client
             completion:(void(^_Nonnull)(PowerAuthCoreTask * _Nonnull task, id _Nullable response, NSError * _Nullable error))completion
{
    self = [super init];
    if (self) {
        _task = task;
        _client = client;
        _completion = completion;
    }
    return self;
}

- (nullable id<PowerAuthOperationTask>) processNext
{
    NSError * localError = nil;
    PowerAuthCoreRequest * request = [_client.sessionInterface writeTaskWithSession:^PowerAuthCoreRequest* _Nullable(PowerAuthCoreSession * session, NSError ** error) {
        return [_task nextRequest:error];
    } error:&localError];
    if (localError) {
        [self setFinished:nil error:localError];
        return nil;
    }
    if (request) {
        // Next request is scheduled
        _current_async_operation = [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * _Nonnull request, id  _Nullable response, NSError * _Nullable error) {
            [self processNext];
        }];
        return self;
    }
    if (!_task.isDone) {
        [self setFinished:nil error:PA2MakeError(PowerAuthErrorCode_OperationCancelled, @"Task did not create next request")];
        return nil;
    }
    [self setFinished:_task.responseObject error:nil];
    return nil;
}

- (void) setFinished:(id)result error:(NSError*)error
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!_task.isCanceled && _completion) {
            _completion(_task, result, error);
            _current_async_operation = nil;
            _completion = nil;
            _task = nil;
            _client = nil;
        }
    });
}

- (BOOL) isCancelled
{
    return [_task isCanceled];
}

- (void) cancel
{
    if (_task.isCanceled) {
        return;
    }
    [_client.sessionInterface writeTaskWithSession:^id _Nullable(PowerAuthCoreSession * session, NSError ** error) {
        [_task cancel];
        return nil;
    } error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        [_current_async_operation cancel];
        _current_async_operation = nil;
        _completion = nil;
        _task = nil;
        _client = nil;
    });
}

@end
