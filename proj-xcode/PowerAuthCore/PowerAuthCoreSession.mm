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

#pragma mark - Read / Write access

- (BOOL) requireReadAccess:(NSError**)error
{
    id<PowerAuthCoreSessionDelegate> delegate = _delegate;
    if (delegate) {
        if (![delegate requireReadAccess]) {
            NSString * message = [NSString stringWithFormat:@"Read access not granted for session data. Instance: %@", _configuration.instanceId];
            if (error) {
                *error = powerAuth::BuildCoreNSError(PowerAuthCoreError_InternalError, message);
            } else {
                PowerAuthCoreLog(@"ERROR: %@", message);
            }
            return NO;
        }
    }
    return YES;
}

- (BOOL) requireWriteAccess:(NSError**)error
{
    id<PowerAuthCoreSessionDelegate> delegate = _delegate;
    if (delegate) {
        if (![delegate requireWriteAccess]) {
            NSString * message = [NSString stringWithFormat:@"Write access not granted for session data. Instance: %@", _configuration.instanceId];
            if (error) {
                *error = powerAuth::BuildCoreNSError(PowerAuthCoreError_InternalError, message);
            } else {
                PowerAuthCoreLog(@"ERROR: %@", message);
            }
            return NO;
        }
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
        return [[PowerAuthCoreRequest alloc] initWithRequest:request withBuilder:^id(const powerAuth::Request &request) {
            auto response = std::dynamic_pointer_cast<powerAuth::ActivationResult>(request.getResponseObject());
            if (!response) {
                throw Exception(EC_InternalError, "No ActivationResult object created");
            }
            return [[PowerAuthCoreActivationResult alloc] initWithActivationResult:*response];
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
        auto credentials = InitialCredentials::credentials(password.passObjRef.passwordData(), biometry);
        auto request = _session->confirmActivation(credentials);
        return [[PowerAuthCoreRequest alloc] initWithRequest:request];
    } catch (...) {
        if (error) {
            *error = BuildNSErrorFromException();
        }
        return nil;
    }
}


#pragma mark - Data signing

+ (nullable NSData*) prepareKeyValueDictionaryForDataSigning:(nonnull NSDictionary<NSString*, NSString*>*)dictionary
{
//    __block std::map<std::string, std::string> map;
//    __block BOOL error = NO;
//    [dictionary enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * stop) {
//        if (![key isKindOfClass:[NSString class]] || ![value isKindOfClass:[NSString class]]) {
//            CC7_ASSERT(false, "Wrong type of object or key in provided NSDictionary.");
//            *stop = error = YES;
//            return;
//        }
//        map[std::string(key.UTF8String)] = std::string(value.UTF8String);
//    }];
//    if (error) {
//        return nil;
//    }
//    cc7::ByteArray normalized_data = Session::prepareKeyValueMapForDataSigning(map);
//    return cc7::objc::CopyToNSData(normalized_data);
    return nil;
}


- (BOOL) verifyServerSignedData:(nonnull PowerAuthCoreSignedData*)signedData
{
    return NO;;
}


#pragma mark - Signature keys management

- (BOOL) changeUserPassword:(nonnull PowerAuthCorePassword *)old_password newPassword:(nonnull PowerAuthCorePassword*)new_password
{
    return NO;
}

- (BOOL) hasBiometryFactor
{
    return NO;
}

- (BOOL) removeBiometryFactor
{
    return NO;
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
