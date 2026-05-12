/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PowerAuthEncryptor.h"
#import "PA2PrivateMacros.h"

#import <PowerAuthCore/PowerAuthCoreEncryptorFactory.h>

@implementation PowerAuthEncryptedRequest

- (instancetype) initWithCoreRequest:(PowerAuthCoreEncryptedRequest*)request
{
    self = [super init];
    if (self) {
        _requestBody = request.requestBody;
        NSMutableArray * headers = [NSMutableArray array];
        [request.requestHeaders enumerateObjectsUsingBlock:^(PowerAuthCoreHttpHeader * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            [headers addObject:[PowerAuthHttpHeader createWithCoreHeader:obj]];
        }];
        _requestHeaders = headers;
    }
    return self;
}

@end

@implementation PowerAuthEncryptedResponse
{
    PowerAuthCoreEncryptedResponse * _response;
}

- (nullable instancetype) initWithJsonRepresentation:(nonnull NSDictionary*)jsonRepresentation
                                               error:(NSError*_Nullable*_Nullable)error
{
    self = [super init];
    if (self) {
        NSError * localError = nil;
        _response = [[PowerAuthCoreEncryptedResponse alloc] initWithJsonRepresentation:jsonRepresentation
                                                                                 error:&localError];
        if (localError) {
            PA2WrapError(localError, error);
            return nil;
        }
    }
    return self;
}

- (nullable instancetype) initWithResponseBody:(nonnull NSData*)responseBody
                                         error:(NSError*_Nullable*_Nullable)error
{
    self = [super init];
    if (self) {
        NSError * localError = nil;
        _response = [[PowerAuthCoreEncryptedResponse alloc] initWithResponseBody:responseBody
                                                                           error:&localError];
        if (localError) {
            PA2WrapError(localError, error);
            return nil;
        }
    }
    return self;
}

- (PowerAuthCoreEncryptedResponse*) coreResponse
{
    return _response;
}

@end

@implementation PowerAuthEncryptor
{
    PowerAuthCoreEncryptor * _encryptor;
}

- (instancetype) initWithCoreEncryptor:(PowerAuthCoreEncryptor*)coreEncryptor
{
    self = [super init];
    if (self) {
        _encryptor = coreEncryptor;
    }
    return self;
}

- (PowerAuthEncryptorScope) scope
{
    return (PowerAuthEncryptorScope)[_encryptor scope];
}

- (BOOL) canEncryptRequest
{
    return _encryptor.canEncryptRequest;
}

- (BOOL) canDecryptResponse
{
    return _encryptor.canDecryptResponse;
}

- (nullable PowerAuthEncryptedRequest*) encryptRequest:(nullable NSData*)requestBody
                                                 error:(NSError*_Nullable*_Nullable)error
{
    NSError * localError = nil;
    PowerAuthCoreEncryptedRequest * request = [_encryptor encryptRequest:requestBody error:&localError];
    if (localError) {
        PA2WrapError(localError, error);
        return nil;
    }
    return [[PowerAuthEncryptedRequest alloc] initWithCoreRequest:request];
}

- (nullable NSData*) decryptResponse:(nonnull PowerAuthEncryptedResponse*)response
                               error:(NSError*_Nullable*_Nullable)error
{
    NSError * localError = nil;
    NSData * decrypted = [_encryptor decryptResponse:response.coreResponse
                                               error:&localError];
    if (localError) {
        PA2WrapError(localError, error);
        return nil;
    }
    return decrypted;
}

@end
