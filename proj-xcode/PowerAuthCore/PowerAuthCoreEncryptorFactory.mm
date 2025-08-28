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

#include <PowerAuth/Encryptor.h>

#import <PowerAuthCore/PowerAuthCoreEncryptorFactory.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace cc7;
using namespace powerAuth;

// MARK: - Factory

@implementation PowerAuthCoreEncryptorFactory
{
    IClientEncryptorFactoryPtr _factory;
}

- (instancetype) initWithFactory:(IClientEncryptorFactoryPtr)factory
{
    self = [super init];
    if (self) {
        _factory = factory;
    }
    return self;
}

- (nullable PowerAuthCoreEncryptor*) createEncryptorWithScope:(PowerAuthCoreEncryptorScope)scope
                                                  error:(NSError*_Nullable*_Nullable)error
{
    try {
        if (scope == PowerAuthCoreEncryptorScope_None) {
            throw Exception(EC_WrongParameter, "PowerAuthCoreEncryptorScope_None cannot be used");
        }
        auto encryptorId = (scope == PowerAuthCoreEncryptorScope_Application)
                            ? EncryptorId::APPLICATION_SCOPE_GENERIC
                            : EncryptorId::ACTIVATION_SCOPE_GENERIC;
        auto encryptor = _factory->getClientEncryptor(encryptorId);
        return [[PowerAuthCoreEncryptor alloc] initWithEncryptor:encryptor
                                                           scope:scope];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) fetchTemporaryKeyForScope:(PowerAuthCoreEncryptorScope)scope
                                                       error:(NSError*_Nullable*_Nullable)error
{
    try {
        if (scope == PowerAuthCoreEncryptorScope_None) {
            throw Exception(EC_WrongParameter, "PowerAuthCoreEncryptorScope_None cannot be used");
        }
        auto request = _factory->getTemporaryKeyRequest( static_cast<EncryptorScope>(scope));
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
        
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (BOOL) hasPendingRequestForTemporaryKeyWithScope:(PowerAuthCoreEncryptorScope)scope
{
    if (scope != PowerAuthCoreEncryptorScope_None) {
        return _factory->hasPendingTemporaryKeyRequest(static_cast<EncryptorScope>(scope));
    }
    return NO;
}

- (BOOL) hasTemporaryKeyForScope:(PowerAuthCoreEncryptorScope)scope
{
    if (scope != PowerAuthCoreEncryptorScope_None) {
        return _factory->hasTemporaryKey(static_cast<EncryptorScope>(scope));
    }
    return NO;
}

@end


// MARK: - Encryptor

@implementation PowerAuthCoreEncryptor
{
    IClientEncryptorPtr _encryptor;
}

- (instancetype) initWithEncryptor:(IClientEncryptorPtr)encryptor
                             scope:(PowerAuthCoreEncryptorScope)scope
{
    self = [super init];
    if (self) {
        _encryptor = encryptor;
        _scope = scope;
    }
    return self;
}

- (BOOL) canEncryptRequest
{
    return _encryptor->canEncryptRequest();
}

- (BOOL) canDecryptResponse
{
    return _encryptor->canDecryptResponse();
}

- (nullable PowerAuthCoreEncryptedRequest*) encryptRequest:(NSData*)requestBody
                                                     error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto request = _encryptor->encryptRequest(ByteRange(requestBody.bytes, requestBody.length));
        return [[PowerAuthCoreEncryptedRequest alloc] initWithEncryptedRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable NSData*) decryptResponse:(nonnull PowerAuthCoreEncryptedResponse*)response
                               error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto result = _encryptor->decryptResponse(response.responseRef);
        return cc7::objc::CopyToNSData(result);
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

@end

// MARK: - Request & Response


@implementation PowerAuthCoreEncryptedRequest

- (instancetype) initWithEncryptedRequest:(const EncryptedRequest&)request
{
    self = [super init];
    if (self) {
        _requestBody = cc7::objc::CopyToNSData(cc7::json::JsonWriter::toJsonData(request.requestPayload));
        _requestHeaders = BuildNSArrayWithHeaders(request.requestHeaders);
    }
    return self;
}

@end

@implementation PowerAuthCoreEncryptedResponse
{
    powerAuth::EncryptedResponse _response;
}

- (nullable instancetype) initWithJsonRepresentation:(nonnull NSDictionary*)jsonRepresentation
                                               error:(NSError*_Nullable*_Nullable)error;
{
    try {
        auto json = cc7::objc::JsonValueFromObjC(jsonRepresentation);
        self = [super init];
        if (self) {
            _response.responsePayload = json;
        }
        return self;
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable instancetype) initWithResponseBody:(nonnull NSData*)responseBody
                                         error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto json = cc7::json::JsonReader::fromJsonData(ByteRange(responseBody.bytes, responseBody.length));
        self = [super init];
        if (self) {
            _response.responsePayload = json;
        }
        return self;
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (const powerAuth::EncryptedResponse&) responseRef
{
    return _response;
}

@end
