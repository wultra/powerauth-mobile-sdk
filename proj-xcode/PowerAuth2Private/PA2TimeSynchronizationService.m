/*
 * Copyright 2023 Wultra s.r.o.
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

#import "PA2TimeSynchronizationService.h"
#import "PA2CoreHttpClient.h"
#import "PA2GroupedTask.h"
#import "PA2PrivateMacros.h"
#import "PowerAuthServerStatus+Private.h"

#import "PowerAuthLog.h"
#import <UIKit/UIApplication.h>

#pragma mark - Task interface

/// The `PA2GetSystemStatusTask` implements grouped task that gets server status information from the server.
@interface PA2GetSystemStatusTask : PA2GroupedTask<PowerAuthServerStatus*>

- (instancetype) initWithHttpClient:(PA2CoreHttpClient*)httpClient
                        coreService:(PowerAuthCoreTimeService*)coreService
                         sharedLock:(id<NSLocking>)sharedLock
                           delegate:(id<PA2GetSystemStatusTaskDelegate>)delegate;

@end

#pragma mark - Task implementation

@implementation PA2GetSystemStatusTask
{
    PA2CoreHttpClient * _client;
    PowerAuthCoreTimeService * _coreService;
    __weak id<PA2GetSystemStatusTaskDelegate> _delegate;
}

- (instancetype) initWithHttpClient:(PA2CoreHttpClient *)httpClient
                        coreService:(PowerAuthCoreTimeService*)coreService
                         sharedLock:(id<NSLocking>)sharedLock
                           delegate:(id<PA2GetSystemStatusTaskDelegate>)delegate
{
    self = [super initWithSharedLock:sharedLock taskName:@"GetSystemStatus"];
    if (self) {
        _client = httpClient;
        _coreService = coreService;
        _delegate = delegate;
    }
    return self;
}

- (void) onTaskStart
{
    [super onTaskStart];

    NSError * error = nil;
    PowerAuthCoreRequest * request = [_coreService createTimeSynchronizationRequest:&error];
    if (error) {
        [self complete:nil error:error];
        return;
    }
    
    id<PowerAuthOperationTask> task = [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * _Nonnull request, id  _Nullable response, NSError * _Nullable error) {
        PowerAuthServerStatus * serverStatus = nil;
        if (!error) {
            serverStatus = [[PowerAuthServerStatus alloc] initWithCoreServerStatus:request.responseObject];
            if (!serverStatus) {
                error = PA2MakeError(PowerAuthErrorCode_NetworkError, @"Failed to create server status from response");
            }
        }
        [self complete:serverStatus error:error];
    }];
    [self replaceCancelableOperation:task];
}

- (void) onTaskCompleteWithResult:(PowerAuthServerStatus*)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getSystemStatusTask:self didFinishedWithStatus:result error:error];
}

@end


#pragma mark - Service implementation

@implementation PA2TimeSynchronizationService
{
    id<NSLocking> _lock;
    BOOL _receiveNotifications;
    
    NSTimeInterval _localTimeAdjustment;
    NSTimeInterval _localTimeAdjustmentPrecision;
    
    PowerAuthCoreTimeService * _coreService;
    PA2CoreHttpClient * _httpClient;
    PA2GetSystemStatusTask * _statusTask;
}

- (instancetype) initWithCoreService:(PowerAuthCoreTimeService*)coreService
                          httpClient:(PA2CoreHttpClient*)httpClient
                          sharedLock:(id<NSLocking>)sharedLock
{
    self = [super init];
    if (self) {
        _coreService = coreService;
        _httpClient = httpClient;
        _lock = sharedLock;
    }
    return self;
}

- (void) dealloc
{
    [self unsubscribeForSystemNotificationsImpl];
}

#pragma mark - PowerAuthTimeSynchronizationService protocol -

- (BOOL) isTimeSynchronized
{
    return [_coreService isTimeSynchronized];
}

- (NSTimeInterval) localTimeAdjustment
{
    return [_coreService localTimeAdjustment];
}

- (NSTimeInterval) localTimeAdjustmentPrecision
{
    return [_coreService localTimeAdjustmentPrecision];
}

- (NSTimeInterval) currentTime
{
    return [_coreService currentTime];
}

- (void) resetTimeSynchronization
{
    [self resetTimeSynchronizationImpl:NO];
}

- (id) synchronized:(id(^)(void))block
{
    [_lock lock];
    id result = block();
    [_lock unlock];
    return result;
}

- (void) resetTimeSynchronizationImpl:(BOOL)fromNotification
{
    [self synchronized:^id{
        if (!fromNotification || _receiveNotifications) {
            // TODO: this is potentially problematic. we should re-synchronize the time instead
            [_coreService resetTimeSynchronization];
        }
        return nil;
    }];
}

- (id<PowerAuthOperationTask>) synchronizeTimeWithCallback:(void (^)(NSError *))callback
                                             callbackQueue:(dispatch_queue_t)callbackQueue
{
    if (callbackQueue == nil) {
        callbackQueue = dispatch_get_main_queue();
    }
    return [self fetchServerStatus:^(PowerAuthServerStatus *status, NSError *error) {
        callback(error);
    } callbackQueue:callbackQueue];
}

- (id<PowerAuthOperationTask>) fetchServerStatus:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
                                   callbackQueue:(dispatch_queue_t)callbackQueue
{
    if (callbackQueue == nil) {
        callbackQueue = dispatch_get_main_queue();
    }
    return [self synchronized:^id{
        id<PowerAuthOperationTask> task = [_statusTask createChildTask:callback queue:callbackQueue];
        if (!task) {
            _statusTask = [[PA2GetSystemStatusTask alloc] initWithHttpClient:_httpClient
                                                                 coreService:_coreService
                                                                  sharedLock:_lock
                                                                    delegate:self];
            task = [_statusTask createChildTask:callback queue:callbackQueue];
        }
        return task;
    }];
}

#pragma mark - Task completion and cancel

- (void)getSystemStatusTask:(PA2GetSystemStatusTask *)task didFinishedWithStatus:(PowerAuthServerStatus *)status error:(NSError *)error
{
    // Lock is acquired, because this is called from the task's completion that use the same shared lock internally.
    if (task == _statusTask) {
        _statusTask = nil;
        // This is the reference to task which is going to finish its execution soon.
        // The ivar no longer holds the reference to the task, but we should keep that reference
        // for a little bit longer, to guarantee, that we don't destroy the object in the middle
        // of callback processing.
        [[NSOperationQueue mainQueue] addOperationWithBlock:^{
            // The following call does nothing, because the old task is no longer stored
            // in the `_statusTask` ivar. It just guarantees that the object will be alive
            // during waiting to execute the operation block.
            [self getSystemStatusTask:task didFinishedWithStatus:nil error:nil];
        }];
    }
}

- (void)cancelAllPendingRequests
{
    [self synchronized:^id{
        [_statusTask cancel];
        return nil;
    }];
}


#pragma mark - Notifications -

- (void) subscribeForSystemNotifications
{
    [self synchronized:^id{
        if (!_receiveNotifications) {
            _receiveNotifications = YES;
            // Register this instance for system notifications
            [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(willEnterForeground:) name:UIApplicationWillEnterForegroundNotification object:nil];
        }
        return nil;
    }];
}

- (void) unsubscribeForSystemNotifications
{
    [self synchronized:^id{
        [self unsubscribeForSystemNotificationsImpl];
        return nil;
    }];
}

- (void) unsubscribeForSystemNotificationsImpl
{
    if (_receiveNotifications) {
        _receiveNotifications = NO;
        [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationWillEnterForegroundNotification object:nil];
    }
}

- (void) willEnterForeground:(id)sender
{
    [self resetTimeSynchronizationImpl:YES];
}

@end
