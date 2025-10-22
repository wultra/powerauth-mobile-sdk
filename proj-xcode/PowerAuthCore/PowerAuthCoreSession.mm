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

#include <PowerAuth/Session.h>

#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace cc7;
using namespace powerAuth;

@implementation PowerAuthCoreSession
{
    SessionPtr _session;
    BOOL _hasDelegate;
    __weak id<PowerAuthCoreSessionDelegate> _delegate;
}

#pragma mark - Initialization / Reset

- (instancetype) initWithSession:(SessionPtr)session
                   configuration:(PowerAuthCoreConfig*)configuration
                        delegate:(id<PowerAuthCoreSessionDelegate>)delegate
{
    self = [super init];
    if (self) {
        _configuration = configuration;
        _session = session;
        _delegate = delegate;
        _hasDelegate = delegate != nil;
        _timeSynchronizationService = [[PowerAuthCoreTimeService alloc] initWithService:_session->getTimeService()];
    }
    return self;
}

+ (nullable instancetype) createWithConfiguration:(nonnull PowerAuthCoreConfig*)configuration
                                         delegate:(nullable id<PowerAuthCoreSessionDelegate>)delegate
                                            error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto session = Session::createInstance(configuration.configurationRef);
        return [[PowerAuthCoreSession alloc] initWithSession:session
                                               configuration:configuration
                                                    delegate:delegate];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

+ (nullable instancetype) createWithConfiguration:(nonnull PowerAuthCoreConfig*)configuration
                                            error:(NSError*_Nullable*_Nullable)error
{
    return [self createWithConfiguration:configuration delegate:nil error:error];
}

- (void) resetSession
{
    [self requireWriteAccess:nil];
    _session->resetState();
}

- (id<PowerAuthCoreSessionDelegate>) delegate
{
    return _delegate;
}

- (void) setDelegate:(id<PowerAuthCoreSessionDelegate>)delegate
{
    _delegate = delegate;
    _hasDelegate = delegate != nil;
}

#pragma mark - Read / Write access

static void _ReportError(PowerAuthCoreError code, NSString * message, NSError ** outError)
{
    if (outError) {
        *outError = powerAuth::BuildCoreNSError(code, message);
    } else {
        PowerAuthCoreLog(@"ERROR: %@", message);
    }
}
                        
- (BOOL) requireReadAccess:(NSError**)error
{
    id<PowerAuthCoreSessionDelegate> delegate = _delegate;
    if (delegate) {
        if (![delegate requireReadAccess]) {
            _ReportError(PowerAuthCoreError_InternalError,
                         [NSString stringWithFormat:@"Read access not granted for session data. Instance: %@", _configuration.instanceId],
                         error);
            return NO;
        }
    } else if (_hasDelegate) {
        _ReportError(PowerAuthCoreError_InternalError,
                     [NSString stringWithFormat:@"PowerAuthCoreSessionDelegate is no longer valid. Instance: %@", _configuration.instanceId],
                     error);
        return NO;
    }
    return YES;
}

- (BOOL) requireWriteAccess:(NSError**)error
{
    id<PowerAuthCoreSessionDelegate> delegate = _delegate;
    if (delegate) {
        if (![delegate requireWriteAccess]) {
            _ReportError(PowerAuthCoreError_InternalError,
                         [NSString stringWithFormat:@"Write access not granted for session data. Instance: %@", _configuration.instanceId],
                         error);
            return NO;
        }
    } else if (_hasDelegate) {
        _ReportError(PowerAuthCoreError_InternalError,
                     [NSString stringWithFormat:@"PowerAuthCoreSessionDelegate is no longer valid. Instance: %@", _configuration.instanceId],
                     error);
        return NO;
    }
    return YES;
}

#pragma mark - Read only getters

- (NSString*) applicationKey
{
    return cc7::objc::CopyToNSString(_session->getConfiguration()->applicationKey());
}

- (NSString*) instanceId
{
    return cc7::objc::CopyToNSString(_session->getConfiguration()->instanceId());
}

- (PowerAuthCoreAlgorithm) currentAlgorithm
{
    [self requireReadAccess:nil];
    return static_cast<PowerAuthCoreAlgorithm>(_session->getPowerAuthSpec()->algorithm());
}

- (BOOL) canCreateActivation
{
    [self requireReadAccess:nil];
    return _session->canCreateActivation();
}

- (BOOL) hasPendingCreateActivation
{
    [self requireReadAccess:nil];
    return _session->hasPendingCreateActivation();
}

- (BOOL) hasValidActivationData
{
    [self requireReadAccess:nil];
    return _session->hasValidActivationData();
}

- (BOOL) hasProtocolUpgradeAvailable
{
    [self requireReadAccess:nil];
    // TODO: missing impl.
    return NO;
}

- (BOOL) hasPendingProtocolUpgrade
{
    [self requireReadAccess:nil];
    // TODO: missing impl.
    return NO;
}

- (PowerAuthCoreProtocolVersion) protocolVersion
{
    [self requireReadAccess:nil];
    return (PowerAuthCoreProtocolVersion) _session->getProtocolVersion();
}

#pragma mark - Serialization

- (nullable NSData*) serializedState:(NSError*_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        return cc7::objc::CopyToNSData(_session->saveState());
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}


- (BOOL) deserializeState:(nonnull NSData *)state
                    error:(NSError*_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return NO;
    }
    try {
        _session->loadState(ByteRange(state.bytes, state.length));
        return YES;
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return NO;
    }
}

- (BOOL) isModifiedState
{
    if (![self requireReadAccess:nil]) {
        // TODO: log failure
        return YES;
    }
    return _session->isModifiedState();
}

#pragma mark - Activation

- (nullable NSString*) activationIdentifier
{
    [self requireReadAccess:nil];
    return cc7::objc::CopyToNullableNSString(_session->activationId());
}

- (nullable NSString*) activationFingerprint
{
    [self requireReadAccess:nil];
    return cc7::objc::CopyToNullableNSString(_session->activationFingerprint());
}

- (nullable PowerAuthCoreRequest*) createActivation:(nonnull NSDictionary*)L1Data
                                         withL2Data:(nonnull NSDictionary*)L2Data
                                              error:(NSError*_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return nil;
    }
    try {
        auto L1 = objc::JsonValueFromObjC(L1Data);
        auto L2 = objc::JsonValueFromObjC(L2Data);
        auto request = _session->createActivation(L1, L2);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto result = std::dynamic_pointer_cast<powerAuth::ActivationResult>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No ActivationResult object created");
            }
            return [[PowerAuthCoreActivationResult alloc] initWithActivationResult:*result];
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) confirmActivationWithPassword:(nonnull PowerAuthCorePassword*)password
                                                           error:(NSError*_Nullable*_Nullable)error
{
    return [self confirmActivationWithPassword:password
                               withBiometryKek:nil
                                         error:error];
}

- (nullable PowerAuthCoreRequest*) confirmActivationWithPassword:(nonnull PowerAuthCorePassword*)password
                                                 withBiometryKek:(nullable PowerAuthCoreData*)biometryKek
                                                           error:(NSError*_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return nil;
    }
    try {
        auto biometry = biometryKek ? biometryKek.byteArrayRef : ByteRange();
        auto credentials = InitialCredentials::credentials(password.passObjRef->passwordData(), biometry);
        auto request = _session->confirmActivation(credentials);
        if (request) {
            return [[PowerAuthCoreRequest alloc] initWithRequest:request];
        }
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (nullable PowerAuthCoreTask*) fetchActivationStatus:(NSError*_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto task = _session->fetchActivationStatus();
        return [[PowerAuthCoreTask alloc] initWithTask:task withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto status = std::dynamic_pointer_cast<powerAuth::ActivationStatus>(response);
            if (!status) {
                throw Exception(EC_InternalError, "No ActivationStatus object created");
            }
            return [[PowerAuthCoreActivationStatus alloc] initWithActivationStatus:status];
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) removeActivationWithCredentials:(nonnull PowerAuthCoreCredentials*)credentials
                                                             error:(NSError * _Nullable __autoreleasing * _Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->removeActivation(credentials.credentialsRef);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

#pragma mark - Signature keys management

- (nullable PowerAuthCoreRequest*) verifyPassword:(nonnull PowerAuthCorePassword*)password
                                            error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto request = _session->verifyPassword(password.passObjRef);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) changePassword:(nonnull PowerAuthCorePassword*)oldPassword
                                       toPassword:(nonnull PowerAuthCorePassword*)newPassword
                                            error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto request = _session->changePassword(oldPassword.passObjRef, newPassword.passObjRef);
        if (request) {
            return [[PowerAuthCoreRequest alloc] initWithRequest:request];
        }
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (BOOL) hasBiometryFactor
{
    if (![self requireReadAccess:nil]) {
        return NO;
    }
    try {
        return _session->hasBiometricFactor();
    } catch (...) {
        // TODO: log exception
        return NO;
    }
}

- (nullable PowerAuthCoreRequest*) addBiometryFactorWithPassword:(nonnull PowerAuthCorePassword*)password
                                                 withBiometryKek:(nonnull PowerAuthCoreData *)biometryKek
                                                           error:(NSError **)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->addBiometricFactor(password.passObjRef, biometryKek.byteArrayRef);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) removeBiometryFactor:(NSError*_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return nil;
    }
    
    try {
        auto request = _session->removeBiometricFactor();
        if (request) {
            return [[PowerAuthCoreRequest alloc] initWithRequest:request];
        }
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

#pragma mark - Authentication

- (nullable PowerAuthCoreHttpHeader*) calculateOnlineAuthenticationHeader:(nonnull PowerAuthCoreCredentials*)credentials
                                                            uriIdentifier:(nonnull NSString*)uriIdentifier
                                                               httpMethod:(nonnull NSString*)httpMethod
                                                              requestBody:(nullable NSData*)requestBody
                                                                    error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return nil;
    }
    try {
        auto header = _session->calculateOnlineAuthenticationHeader(*credentials.credentialsRef,
                                                                    objc::CopyFromNSString(uriIdentifier),
                                                                    objc::CopyFromNSString(httpMethod),
                                                                    objc::CopyFromNSData(requestBody));
        return [[PowerAuthCoreHttpHeader alloc] initWithHttpHeader:header];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (nullable NSString*) calculateOfflineAuthenticationCode:(nonnull PowerAuthCoreCredentials*)credentials
                                            uriIdentifier:(nonnull NSString*)uriIdentifier
                                             offlineNonce:(nonnull NSString*)offlineNonce
                                               codeLength:(NSUInteger)codeLength
                                                     data:(nullable NSData*)data
                                                    error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireWriteAccess:error]) {
        return nil;
    }
    try {
        auto code = _session->calculateOfflineAuthenticationCode(*credentials.credentialsRef,
                                                                 objc::CopyFromNSString(uriIdentifier),
                                                                 objc::CopyFromNSString(offlineNonce),
                                                                 objc::CopyFromNSData(data),
                                                                 codeLength);
        return objc::CopyToNSString(code);
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (nullable NSData*) normalizeGetRequestParameters:(nonnull NSDictionary<NSString*, NSString*>*)parameters
                                             error:(NSError *_Nullable*_Nullable)error
{
    __block std::map<std::string, std::string> map;
    __block BOOL failure = NO;
    [parameters enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * stop) {
        if (![key isKindOfClass:[NSString class]] || ![value isKindOfClass:[NSString class]]) {
            *stop = failure = YES;
            return;
        }
        map[objc::CopyFromNSString(key)] = objc::CopyFromNSString(value);
    }];
    if (failure) {
        _ReportError(PowerAuthCoreError_WrongParameter, @"Wrong object type provided in parameters dictionary", error);
        return nil;
    }
    try {
        auto normalized = _session->getAuthenticationService()->normalizeGetRequestParameters(map);
        return objc::CopyToNSData(normalized);
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

#pragma mark - Tokens

- (nullable PowerAuthCoreHttpHeader*) calculateTokenHeader:(nonnull NSString *)tokenIdentifier
                                               tokenSecret:(nonnull NSData*)tokenSecret
                                                     error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto header = _session->calculateTokenHeader(cc7::objc::CopyFromNSString(tokenIdentifier),
                                                     cc7::objc::CopyFromNSData(tokenSecret));
        return [[PowerAuthCoreHttpHeader alloc] initWithHttpHeader:header];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (nullable PowerAuthCoreRequest*) createAccessToken:(nonnull PowerAuthCoreCredentials*)credentials
                                               error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->createAccessToken(credentials.credentialsRef);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto tokenData = std::dynamic_pointer_cast<powerAuth::GetAccessTokenResponse>(response);
            if (!tokenData) {
                throw Exception(EC_InternalError, "No GetAccessTokenResponse object created");
            }
            return [[PowerAuthCoreTokenData alloc] initWithResponse:tokenData];
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

- (nullable PowerAuthCoreRequest*) removeAccessToken:(nonnull NSString *)tokenIdentifier
                                               error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->removeAccessToken(cc7::objc::CopyFromNSString(tokenIdentifier));
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

#pragma mark - Vault operations

- (nullable PowerAuthCoreRequest*) fetchVaultEncryptionKey:(nonnull PowerAuthCoreCredentials*)credentials
                                                     keyId:(PowerAuthCoreVaultEncryptionKeyId)keyId
                                                     index:(UInt64)index
                                                     error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->fetchVaultEncryptionKey(credentials.credentialsRef, static_cast<VaultEncryptionKeyId>(keyId), index);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto dataResponse = std::dynamic_pointer_cast<powerAuth::DataResponse>(response);
            if (!dataResponse) {
                throw Exception(EC_InternalError, "No DataResponse object created");
            }
            return [[PowerAuthCoreData alloc] initWithByteRange:dataResponse->data()];
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}

+ (nullable PowerAuthCoreData*) deriveVaultEncryptionKey:(nonnull PowerAuthCoreData*)vaultKey
                                                   keyId:(PowerAuthCoreVaultEncryptionKeyId)keyId
                                                   index:(UInt64)index
                                                   error:(NSError *_Nullable*_Nullable)error
{
    try {
        auto derived = Session::deriveVaultEncryptionKey(vaultKey.byteArrayRef, index, static_cast<VaultEncryptionKeyId>(keyId));
        return [[PowerAuthCoreData alloc] initWithByteRange:derived];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
    }
    return nil;
}


#pragma mark - Digital signatures

- (BOOL) verifySignature:(nonnull NSData*)signature
                    data:(nonnull NSData*)data
                   keyId:(PowerAuthCoreSignatureKeyId)keyId
                   error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return NO;
    }
    try {
        return _session->verifySignature(cc7::objc::CopyFromNSData(data),
                                         cc7::objc::CopyFromNSData(signature),
                                         static_cast<SignatureKeyId>(keyId));
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return NO;
    }
}

- (BOOL) jwsVerifySignature:(nonnull NSString*)signedData
                compactForm:(BOOL)compactForm
                     strict:(BOOL)strict
                      keyId:(PowerAuthCoreSignatureKeyId)keyId
                      error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return NO;
    }
    try {
        return _session->jwsVerifySignature(cc7::objc::CopyFromNSString(signedData),
                                            static_cast<SignatureKeyId>(keyId),
                                            compactForm,
                                            strict);
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return NO;
    }
}

- (nullable PowerAuthCoreRequest*) signData:(nullable NSData*)data
                                credentials:(nonnull PowerAuthCoreCredentials*)credentials
                                      keyId:(PowerAuthCoreSignatureKeyId)keyId
                                      error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->signData(credentials.credentialsRef,
                                          cc7::objc::CopyFromNSData(data),
                                          static_cast<SignatureKeyId>(keyId));
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto dataResponse = std::dynamic_pointer_cast<powerAuth::DataResponse>(response);
            if (!dataResponse) {
                throw Exception(EC_InternalError, "No DataResponse object created");
            }
            return cc7::objc::CopyToNSData(dataResponse->data());
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

- (nullable PowerAuthCoreRequest*) jwsSignData:(nullable NSData*)data
                                      dataType:(nullable NSString*)dataType
                                   compactForm:(BOOL)compactForm
                                   credentials:(nonnull PowerAuthCoreCredentials*)credentials
                                         keyId:(PowerAuthCoreSignatureKeyId)keyId
                                         error:(NSError *_Nullable*_Nullable)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    try {
        auto request = _session->jwsSignData(credentials.credentialsRef,
                                             cc7::objc::CopyFromNSData(data),
                                             cc7::objc::CopyFromNSString(dataType),
                                             static_cast<SignatureKeyId>(keyId),
                                             compactForm);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::ResponseObjectPtr &response) {
            auto stringResponse = std::dynamic_pointer_cast<powerAuth::StringResponse>(response);
            if (!stringResponse) {
                throw Exception(EC_InternalError, "No DataResponse object created");
            }
            return cc7::objc::CopyToNSString(stringResponse->string());
        }];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}

#pragma mark - External encryption key

- (BOOL) hasExternalEncryptionKey
{
    return NO;
}

#pragma mark - Services

- (PowerAuthCoreEncryptorFactory*) encryptorFactory
{
    // TODO: keep reference internally, but must be updated after the protocol upgrade.
    return [[PowerAuthCoreEncryptorFactory alloc] initWithFactory:_session->getEncryptorFactory()];
}

#pragma mark - Utilities for generic keys

- (PowerAuthCoreData*) generateFactorKek:(NSError**)error
{
    if (![self requireReadAccess:error]) {
        return nil;
    }
    return [[self class] generateFactorKekForProtocolVersion:(PowerAuthCoreProtocolVersion) _session->getProtocolVersion()
                                                       error:error];
}

+ (nullable PowerAuthCoreData*) generateFactorKekForProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
                                                              error:(NSError**)error
{
    auto kek = cc7::crypto::GetRandomData(protocolVersion == PowerAuthCoreProtocolVersion_V4 ? 32 : 16);
    return [[PowerAuthCoreData alloc] initWithByteRange:kek];
}

+ (NSString*) maxSupportedHttpProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
{
    return cc7::objc::CopyToNSString(ProtocolVersion_GetHttpHeaderVersion(static_cast<ProtocolVersion>(protocolVersion)));
}

@end
