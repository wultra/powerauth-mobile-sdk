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

#import "PA2GetSystemStatusTask.h"
#import "PA2HttpClient.h"
#import "PA2RestApiEndpoint.h"

@implementation PA2GetSystemStatusTask
{
    PA2HttpClient * _client;
    __weak id<PA2GetSystemStatusTaskDelegate> _delegate;
}

- (instancetype) initWithHttpClient:(PA2HttpClient *)httpClient sharedLock:(id<NSLocking>)sharedLock delegate:(id<PA2GetSystemStatusTaskDelegate>)delegate
{
    self = [super initWithSharedLock:sharedLock taskName:@"GetSystemStatus"];
    if (self) {
        _client = httpClient;
        _delegate = delegate;
    }
    return self;
}

- (void) onTaskStart
{
    [super onTaskStart];

    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint getSystemStatus];
    id<PowerAuthOperationTask> cancelable = [_client postObject:nil to:endpoint completion:^(PowerAuthRestApiResponseStatus status, PA2GetServerStatusResponse * response, NSError * error) {
        [self complete:response error:error];
    }];
    [self replaceCancelableOperation:cancelable];
}

- (void) onTaskCompleteWithResult:(id)result error:(NSError *)error
{
    [super onTaskCompleteWithResult:result error:error];
    [_delegate getSystemStatusTask:self didFinishedWithStatus:result error:error];
}

@end
