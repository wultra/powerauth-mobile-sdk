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

#import "PowerAuthCoreTask.h"
#import "PowerAuthCorePrivateImpl.h"

@implementation PowerAuthCoreTask
{
    powerAuth::TaskPtr _task;
    PowerAuthCoreResponseBuilder _responseBuilder;
    BOOL _responseCaptured;
    id _responseObject;
    id _responseJson;
}

- (id) initWithTask:(powerAuth::TaskPtr&)task
{
    return [self initWithTask:task withBuilder:nil];
}

- (id) initWithTask:(powerAuth::TaskPtr&)task
        withBuilder:(PowerAuthCoreResponseBuilder)builder
{
    if (!task) {
        throw powerAuth::Exception(powerAuth::EC_InternalError, "No task object provided");
    }

    self = [super init];
    if (self) {
        _task = task;
        _responseBuilder = builder;
    }
    return self;
}

- (NSString*) taskName
{
    return cc7::objc::CopyToNSString(_task->name());
}

- (BOOL) isDone
{
    return _task->isDone();
}

- (BOOL) isCanceled
{
    return _task->isCanceled();
}

- (BOOL) isCompleted
{
    return _task->isCompleted();
}

- (BOOL) isFailed
{
    return _task->isFailed();
}

- (id) responseObject
{
    [self updateResponse];
    return _responseObject;
}

- (id) responseJson
{
    [self updateResponse];
    return _responseJson;
}

- (void) updateResponse
{
    if (_task->isCompleted() && !_responseCaptured) {
        _responseCaptured = YES;
        try {
            _responseJson   = cc7::objc::JsonValueToObjC(_task->getResponseJson());
            if (_responseBuilder) {
                _responseObject = _responseBuilder(_task->getResponseObject());
                _responseBuilder = nil;
            }
        } catch (...) {
            _task->setFailed(std::current_exception());
            _failure = powerAuth::BuildNSErrorFromException(std::current_exception());
            _responseObject = nil;
            _responseJson = nil;
        }
    }
}

- (void) cancel
{
    _task->cancel();
}

- (nullable PowerAuthCoreRequest*) nextRequest:(NSError*_Nullable*_Nullable)error
{
    try {
        auto request = _task->getNextRequest();
        return request ? [[PowerAuthCoreRequest alloc] initWithRequest:request] : nil;
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        if (error) {
            *error = _failure;
        }
        return nil;
    }
}

@end
