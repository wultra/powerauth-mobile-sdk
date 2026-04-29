/*
 * Copyright 2024 Wultra s.r.o.
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

#import "PA2KeystoreService.h"
#import "PA2PrivateMacros.h"
#import "PA2CoreHttpClient.h"
#import "PA2GroupedTask.h"

#import <PowerAuth2/PowerAuthLog.h>

#pragma mark - Task interface

@interface PA2GetTemporaryKeyTask : PA2GroupedTask<id>

- (nonnull instancetype) initWithHttpClient:(nonnull PA2CoreHttpClient*)httpClient
                            sessionProvider:(nonnull id<PowerAuthCoreSessionProvider>)sessionProvider
                                 sharedLock:(nonnull id<NSLocking>)sharedLock
                             encryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope
                                   delegate:(nonnull id<PA2GetTemporaryKeyTaskDelegate>)delegate;

@end


#pragma mark - Task implementation

@implementation PA2GetTemporaryKeyTask
{
    PA2CoreHttpClient * _client;
    id<PowerAuthCoreSessionProvider> _sessionProvider;
    __weak id<PA2GetTemporaryKeyTaskDelegate> _delegate;
    PowerAuthCoreEncryptorScope _encryptorScope;
    BOOL _isApplicationScope;
}

- (instancetype) initWithHttpClient:(PA2CoreHttpClient*)httpClient
                    sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                         sharedLock:(id<NSLocking>)sharedLock
                     encryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope
                           delegate:(id<PA2GetTemporaryKeyTaskDelegate>)delegate
{
    BOOL isAppScope = encryptorScope ==  PowerAuthCoreEncryptorScope_Application;
    self = [super initWithSharedLock:sharedLock
                            taskName:isAppScope ? @"GetTempKey-App" : @"GetTempKey-Act"];
    if (self) {
        _client = httpClient;
        _sessionProvider = sessionProvider;
        _encryptorScope = encryptorScope;
        _delegate = delegate;
        _isApplicationScope = isAppScope;
    }
    return self;
}

- (void) onTaskStart
{
    [super onTaskStart];
    
    NSError * error = nil;
    PowerAuthCoreRequest * request = [_sessionProvider readTaskWithSession:^PowerAuthCoreRequest*(PowerAuthCoreSession * session, NSError ** error) {
        return [[session encryptorFactory] fetchTemporaryKeyForScope:_encryptorScope error:error];
    } error:&error];
    if (error) {
        [self complete:nil error:error];
        return;
    }
    id<PowerAuthOperationTask> cancelable = [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * _Nonnull request, id  _Nullable response, NSError * _Nullable error) {
        [self complete:nil error:error];
    }];
    [self replaceCancelableOperation:cancelable];
}

- (void) onTaskCompleteWithResult:(id)result error:(NSError*)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getTemporaryKeyTask:self didFinishWithError:error];
}

@end



#pragma mark - Service implementation

@implementation PA2KeystoreService
{
    id<NSLocking> _lock;
    id<PA2SessionInterface> _sessionInterface;
    PA2CoreHttpClient * _httpClient;
    
    PA2GetTemporaryKeyTask * _getAppKeyTask;
    PA2GetTemporaryKeyTask * _getActKeyTask;
}

- (instancetype) initWithHttpClient:(PA2CoreHttpClient*)httpClient
                   sessionInterface:(id<PA2SessionInterface>)sessionInterface
                         sharedLock:(id<NSLocking>)sharedLock
{
    self = [super init];
    if (self) {
        _lock = sharedLock;
        _sessionInterface = sessionInterface;
        _httpClient = httpClient;
    }
    return self;
}

- (id<PowerAuthOperationTask>) createKeyForEncryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope
                                                 callback:(void (^)(NSError *))callback
                                            callbackQueue:(dispatch_queue_t)callbackQueue
{
    if (!callbackQueue) {
        callbackQueue = dispatch_get_main_queue();
    }
    [_lock lock];
    id<PowerAuthOperationTask> task = nil;
    if (![self hasKeyForEncryptorScope:encryptorScope]) {
        task = [self getTaskForScope:encryptorScope callback:^(id foo, NSError * error) {
            callback(error);
        } callbackQueue:callbackQueue];
    }
    [_lock unlock];
    if (!task) {
        // temporary key is available, call the callback immediately
        callback(nil);
    }
    return task;
}

- (BOOL) hasKeyForEncryptorScope:(PowerAuthCoreEncryptorScope)encryptorScope
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [[session encryptorFactory] hasTemporaryKeyForScope:encryptorScope];
    } error:nil];
}

#pragma mark - PA2GetTemporaryKeyTaskDelegate

- (void) getTemporaryKeyTask:(PA2GetTemporaryKeyTask *)task didFinishWithError:(NSError *)error
{
    // Lock is acquired, because this is called from the task's completion that use the same shared lock internally.
    BOOL keepReference;
    if (task == _getActKeyTask) {
        _getActKeyTask = nil;
        keepReference = YES;
    } else if (task == _getAppKeyTask) {
        _getAppKeyTask = nil;
        keepReference = YES;
    } else {
        keepReference = NO;
    }
    if (keepReference) {
        // This is the reference to task which is going to finish its execution soon.
        // The ivar no longer holds the reference to the task, but we should keep that reference
        // for a little bit longer, to guarantee, that we don't destroy the object in the middle
        // of callback processing.
        [[NSOperationQueue mainQueue] addOperationWithBlock:^{
            // The following call does nothing, because the old task is no longer stored
            // in the `_statusTask` ivar. It just guarantees that the object will be alive
            // during waiting to execute the operation block.
            [self getTemporaryKeyTask:task didFinishWithError:nil];
        }];
    }
}

- (id<PowerAuthOperationTask>) getTaskForScope:(PowerAuthCoreEncryptorScope)encryptorScope
                                      callback:(void (^)(id, NSError *))callback
                                 callbackQueue:(dispatch_queue_t)callbackQueue
{
    id<PowerAuthOperationTask> task;
    if (encryptorScope == PowerAuthCoreEncryptorScope_Application) {
        // application scope, use _getAppKeyTask
        task = [_getAppKeyTask createChildTask:callback queue:callbackQueue];
        if (!task) {
            _getAppKeyTask = [self createGroupedTaskForScope:encryptorScope];
            task = [_getAppKeyTask createChildTask:callback queue:callbackQueue];
        }
    } else {
        // application scope, use _getActKeyTask
        task = [_getActKeyTask createChildTask:callback queue:callbackQueue];
        if (!task) {
            _getActKeyTask = [self createGroupedTaskForScope:encryptorScope];
            task = [_getActKeyTask createChildTask:callback queue:callbackQueue];
        }
    }
    return task;
}

- (PA2GetTemporaryKeyTask*) createGroupedTaskForScope:(PowerAuthCoreEncryptorScope)encryptorScope
{
    return [[PA2GetTemporaryKeyTask alloc] initWithHttpClient:_httpClient
                                              sessionProvider:_sessionInterface
                                                   sharedLock:_lock
                                               encryptorScope:encryptorScope
                                                     delegate:self];
}

@end
