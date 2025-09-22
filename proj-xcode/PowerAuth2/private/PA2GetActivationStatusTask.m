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

#import "PA2GetActivationStatusTask.h"
#import "PowerAuthActivationStatus+Private.h"
#import "PA2PrivateMacros.h"
#import "PA2CoreHttpClient.h"
#import "PA2Result.h"

#import <PowerAuth2/PowerAuthLog.h>
#import <PowerAuth2/PowerAuthAuthentication.h>

@import PowerAuthCore;

#pragma mark - Status fetching task

@implementation PA2GetActivationStatusTask
{
    PA2CoreHttpClient * _client;
    id<PowerAuthCoreSessionProvider> _sessionProvider;
    __weak id<PA2GetActivationStatusTaskDelegate> _delegate;
    BOOL _disableUpgrade;
    
    // Runtime variables
    NSInteger _upgradeAttempts;
    BOOL _disableAutoCancel;
    PowerAuthActivationStatus * _receivedStatus;
}

- (id) initWithHttpClient:(PA2CoreHttpClient*)httpClient
          sessionProvider:(id<PowerAuthCoreSessionProvider>)sessionProvider
                 delegate:(id<PA2GetActivationStatusTaskDelegate>)delegate
               sharedLock:(id<NSLocking>)sharedLock
           disableUpgrade:(BOOL)disableUpgrade
{
    self = [super initWithSharedLock:sharedLock taskName:@"GetActivationStatus"];
    if (self) {
        _client = httpClient;
        _sessionProvider = sessionProvider;
        _delegate = delegate;
        _disableUpgrade = disableUpgrade;
        
        _upgradeAttempts = 3;
        _disableAutoCancel = NO;
    }
    return self;
}


#pragma mark - PA2GroupedTask

- (void) onTaskStart
{
    [super onTaskStart];
    [self fetchActivationStatusAndTestUpgrade];
}

- (void) onTaskRestart
{
    [super onTaskRestart];
    _upgradeAttempts = 3;
    _disableAutoCancel = NO;
    _receivedStatus = nil;
}

- (void) onTaskCompleteWithResult:(PowerAuthActivationStatus*)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getActivationStatusTask:self didFinishedWithStatus:result error:error];
}

- (BOOL) shouldCancelWhenNoChildOperationIsSet
{
    return _disableAutoCancel == NO;
}

#pragma mark - Activation status fetcher

/**
 Performs getting status from the server and starts protocol upgrade, if possible.
 */
- (void) fetchActivationStatusAndTestUpgrade
{
    [self fetchActivationStatus:^(PowerAuthActivationStatus *status, NSError *error) {
        [self complete:status error:error];
    }];
}


/**
 Fetch activation status from the server. This is the low level operation, which simply
 receives the status from the server and does no additional processing.
 */
- (void) fetchActivationStatus:(void(^)(PowerAuthActivationStatus *status, NSError *error))callback
{
    NSError* localError = nil;
    PowerAuthCoreTask * task = [_sessionProvider readTaskWithSession:^PowerAuthCoreTask* (PowerAuthCoreSession * session, NSError** error) {
        return [session fetchActivationStatus:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return;
    }
    id<PowerAuthOperationTask> fetchStatusTask = [_client postCoreTask:task completion:^(PowerAuthCoreTask * task, PowerAuthCoreActivationStatus * response, NSError * error) {
        PowerAuthActivationStatus * status;
        if (response) {
            status = [[PowerAuthActivationStatus alloc] initWithCoreStatus:response];
        } else {
            status = nil;
        }
        callback(status, error);
    }];
    [self replaceCancelableOperation:fetchStatusTask];
}

@end

