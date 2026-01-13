/*
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

#include <PowerAuth/Password.h>
#include <PowerAuth/Configuration.h>
#include <PowerAuth/Credentials.h>
#include <PowerAuth/Task.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/TimeService.h>
#include <PowerAuth/AuthenticationService.h>
#include <PowerAuth/TokenService.h>
#include <PowerAuth/ActivationResult.h>
#include <PowerAuth/ActivationStatus.h>
#include <PowerAuth/ProtocolUpgradeResult.h>

#include <cc7/crypto/Crypto.h>
#include <cc7/objc/ObjcHelper.h>
#include <cc7/objc/ObjcJson.h>

#import <PowerAuthCore/PowerAuthCoreLog.h>
#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCoreActivationResult.h>
#import <PowerAuthCore/PowerAuthCoreActivationStatus.h>
#import <PowerAuthCore/PowerAuthCoreTokenData.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeResult.h>

/*
 This header contains various private interfaces, internally used
 in the PowerAuthCore's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

@interface PowerAuthCorePassword (Private)
- (const powerAuth::PasswordPtr &) passObjRef;
@end

@interface PowerAuthCoreData (Private)
- (id) initWithByteRange:(const cc7::ByteRange &)byteRange;
- (const cc7::ByteRange &) byteArrayRef;
@end

@interface PowerAuthCoreConfig (Private)
- (powerAuth::ConfigurationPtr) configurationRef;
@end

/// Lambda for create custom objects when successful response is received.
typedef id(^PowerAuthCoreResponseBuilder)(const powerAuth::ResponseObjectPtr& response);

@interface PowerAuthCoreRequest (Private)
- (id) initWithRequest:(const powerAuth::RequestPtr&)request;
- (id) initWithRequest:(const powerAuth::RequestPtr&)request
           withBuilder:(PowerAuthCoreResponseBuilder)builder;
@end

@interface PowerAuthCoreTask (Private)
- (id) initWithTask:(powerAuth::TaskPtr&)task;
- (id) initWithTask:(powerAuth::TaskPtr&)task
        withBuilder:(PowerAuthCoreResponseBuilder)builder;
@end

@interface PowerAuthCoreCredentials (Private)
- (instancetype) initWithCredentials:(powerAuth::CredentialsPtr)credentials;
- (const powerAuth::CredentialsPtr&) credentialsRef;
@end

@interface PowerAuthCoreServerStatus (Private)
- (instancetype) initWithServerStatus:(const powerAuth::ServerStatusPtr&)serverStatus;
@end

@interface PowerAuthCoreActivationResult (Private)
- (instancetype) initWithActivationResult:(const powerAuth::ActivationResult&)activationResult;
@end

@interface PowerAuthCoreActivationStatus (Private)
- (instancetype) initWithActivationStatus:(const powerAuth::ActivationStatusPtr&)activationStatus;
@end

@interface PowerAuthCoreHttpHeader (Private)
- (instancetype) initWithHttpHeader:(const powerAuth::HttpHeader&)httpHeader;
@end

@interface PowerAuthCoreTokenData (Private)
- (instancetype) initWithResponse:(const powerAuth::GetAccessTokenResponsePtr&)response;
@end

@interface PowerAuthCoreDevicePublicKeyData (Private)
- (instancetype) initWithKeyData:(const powerAuth::DevicePublicKeyData&)keyData;
@end

@interface PowerAuthCoreProtocolUpgradeResult (Private)
- (instancetype) initWithProtocolUpgradeResult:(const powerAuth::ProtocolUpgradeResult&)protocolUpgradeResult;
@end

// Services

@interface PowerAuthCoreTimeService (Private)
- (instancetype) initWithService:(const powerAuth::TimeServicePtr&)timeService;
@end

// Encryptor

@interface PowerAuthCoreEncryptedRequest (Private)
- (instancetype) initWithEncryptedRequest:(const powerAuth::EncryptedRequest&)request;
@end

@interface PowerAuthCoreEncryptedResponse (Private)
- (const powerAuth::EncryptedResponse&) responseRef;
@end

@interface PowerAuthCoreEncryptorFactory (Private)
- (instancetype) initWithFactory:(powerAuth::IClientEncryptorFactoryPtr)factory;
@end

@interface PowerAuthCoreEncryptor (Private)
- (instancetype) initWithEncryptor:(powerAuth::IClientEncryptorPtr)encryptor
                             scope:(PowerAuthCoreEncryptorScope)scope;
@end

// Support functions

namespace powerAuth {

/// Build `NSError` object with given error code and message.
/// - Parameters:
///   - errorCode: Error code.
///   - message: Error message.
/// - Returns: Constructed `NSError`.
extern NSError* BuildCoreNSError(PowerAuthCoreError errorCode, NSString * message);

/// Build `NSError` object from provided `std::exception_ptr`. The function is useful in typical
/// high level `try {} catch (...) {}` statement.
extern NSError* BuildNSErrorFromException(std::exception_ptr ptr = std::current_exception());

/// Build `NSDictionary` object from provided list of HTTP headers.
/// - Parameter headers: Vector with headers.
/// - Returns: NSArray with headers.
extern NSArray<PowerAuthCoreHttpHeader*>* BuildNSArrayWithHeaders(const HttpHeaderList& headers);

} // namespace powerAuth
