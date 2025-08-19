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

#import <PowerAuthCore/PowerAuthCoreRequest.h>
#import "PowerAuthCorePrivateImpl.h"

#include <PowerAuth/Request.h>
#include <cc7/objc/ObjcHelper.h>
#include <cc7/objc/ObjcJson.h>

@implementation PowerAuthCoreRequest
{
    powerAuth::RequestPtr _request;
    PowerAuthCoreResponseBuilder _responseBuilder;
    id _responseObject;
    id _responseJson;
}

- (id) initWithRequest:(powerAuth::RequestPtr&)request
           withBuilder:(PowerAuthCoreResponseBuilder)builder
{
    if (!request) {
        throw powerAuth::Exception(powerAuth::EC_InternalError, "No request object provided");
    }
    self = [super init];
    if (self) {
        _request = std::move(request);
        _responseBuilder = builder;
    }
    return self;
}

- (id) initWithRequest:(powerAuth::RequestPtr&)request
{
    return [self initWithRequest:request withBuilder:nil];
}

- (BOOL) isRequireSynchronizedTime
{
    return _request->requireSynchronizedTime();
}

- (BOOL) isRequireSerialQueue
{
    return _request->requireSerialQueue();
}

- (BOOL) isAllowedInUpgrade
{
    return _request->isAllowedInUpgrade();
}

- (PowerAuthCoreEncryptorScope) encryptorScope
{
    if (_request->isEncrypted()) {
        return static_cast<PowerAuthCoreEncryptorScope>(_request->encryptorScope());
    }
    return PowerAuthCoreEncryptorScope_None;
}

- (BOOL) isAuthenticated
{
    return _request->isAuthenticated();
}

- (NSString*) relativePath
{
    return cc7::objc::CopyToNSString(_request->getRelativePath());
}

- (NSString*) httpMethod
{
    return cc7::objc::CopyToNSString(_request->getHttpMethod());
}

- (NSData*) requestBody
{
    try {
        return cc7::objc::CopyToNSData(_request->getRequestBody());
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        return nil;
    }
}

- (NSDictionary*) requestHeaders
{
    try {
        return powerAuth::BuildNSDictionaryWithHeaders(_request->getRequestHeaders());
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        return nil;
    }
}

- (BOOL) isCompleted
{
    return _request->isCompleted();
}

- (BOOL) isCanceled
{
    return _request->isCanceled();
}

- (BOOL) isFailed
{
    return _request->isFailed();
}

- (BOOL) isDone
{
    return _request->isDone();
}

- (BOOL) cancel
{
    try {
        _request->cancel();
        return YES;
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        return NO;
    }
}

- (BOOL) prepareRequest:(NSError *__autoreleasing *)error
{
    try {
        _failure = nil;
        _request->prepareRequest();
        return YES;
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        if (error) {
            *error = _failure;
        }
        return NO;
    }
}

- (BOOL) processResponse:(NSData *)response error:(NSError * _Nullable __autoreleasing *)error
{
    try {
        _failure = nil;
        _request->processResponse(cc7::objc::CopyFromNSData(response));
        if (_responseBuilder) {
            _responseObject = _responseBuilder(*_request);
            _responseBuilder = nil;
        }
        _responseJson = cc7::objc::JsonValueToObjC(_request->getResponseJson());
        return YES;
    } catch (...) {
        _failure = powerAuth::BuildNSErrorFromException();
        if (error) {
            *error = _failure;
        }
        return NO;
    }
}

- (id) responseObject
{
    if (_request->isCompleted()) {
        return _responseObject;
    }
    return nil;
}

- (id) responseJson
{
    if (_request->isCompleted()) {
        return _responseJson;
    }
    return nil;
}

- (nullable id) executeOperation:(id _Nullable (^_Nonnull)(void))operation
{
    return _request->executeOperation<id>([&operation]() -> id {
        return operation();
    });
}

@end

namespace powerAuth {

NSDictionary* BuildNSDictionaryWithHeaders(const HttpHeaderList& headers)
{
    NSMutableDictionary * result = [NSMutableDictionary dictionaryWithCapacity:headers.size()];
    for (const auto& header : headers) {
        [result setValue:cc7::objc::CopyToNSString(header.headerValue)
                  forKey:cc7::objc::CopyToNSString(header.headerName)];
    }
    return result;
}

} // namespace powerAuth
