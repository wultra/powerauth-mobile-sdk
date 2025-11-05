/**
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

#import "PA2ProtocolUpgradeTask.h"
#import "PA2CoreHttpClient.h"

@import PowerAuthCore;

#pragma mark - Protocol upgrade task

@implementation PA2ProtocolUpgradeTask
{
    PA2CoreHttpClient * _client;
    id<PowerAuthCoreSessionProvider> _sessionProvider;
    __weak id<PA2ProtocolUpgradeTaskDelegate> _delegate;
    PowerAuthCorePassword * _password;
    PowerAuthCoreData * _newBiometryKek;
    
    // Runtime variables
    BOOL _disableAutoCancel;
}

- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
                 password:(PowerAuthCorePassword*) password
           newBiometryKek:(PowerAuthCoreData*) newBiometryKek
{
    self = [super initWithSharedLock:sharedLock taskName:@"ProtocolUpgradeTask"];
    if (self) {
        _client = httpClient;
        _sessionProvider = sessionProvider;
        _delegate = delegate;
        _password = password;
        _newBiometryKek = newBiometryKek;
        
        _disableAutoCancel = NO;
    }
    return self;
}

- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
                 password:(PowerAuthCorePassword*)password
{
    return [self initWithHttpClient:httpClient
                    sessionProvider:sessionProvider
                           delegate:delegate
                         sharedLock:sharedLock
                           password:password
                     newBiometryKek:nil];
}

- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2ProtocolUpgradeTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
{
    return [self initWithHttpClient:httpClient
                    sessionProvider:sessionProvider
                           delegate:delegate
                         sharedLock:sharedLock
                           password:nil
                     newBiometryKek:nil];
}


#pragma mark - PA2GroupedTask

- (void) onTaskStart
{
    [super onTaskStart];
    
    [self startProtocolUpgrade:^(NSError *error) {
        [self complete:nil error:error];
    }];
}

- (void) onTaskRestart
{
    [super onTaskRestart];
}

- (void) onTaskCompleteWithResult:(id)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate startProtocolUpgradeTask:self
                   didFinishedWithError:error
                  newBiometryKekToStore:_newBiometryKek];
}

- (BOOL) shouldCancelWhenNoChildOperationIsSet
{
    return _disableAutoCancel == NO;
}

#pragma mark - Protocol upgrade task procedure start

- (void) startProtocolUpgrade:(void(^)(NSError *error))callback
{
    NSError* localError = nil;
    PowerAuthCoreTask * task = [_sessionProvider writeTaskWithSession:^PowerAuthCoreTask* (PowerAuthCoreSession * session, NSError** error) {
        return [session startProtocolUpgradeWithPassword:_password
                                      withNewBiometryKek:_newBiometryKek
                                                   error:error];
    } error:&localError];
    
    if (localError) {
        callback(localError);
        return;
    }
    
    id<PowerAuthOperationTask> startUpgradeTask = [_client postCoreTask:task completion:^(PowerAuthCoreTask * task, id response, NSError * error) {
        callback(error);
    }];
    
    [self replaceCancelableOperation:startUpgradeTask];
}

@end

