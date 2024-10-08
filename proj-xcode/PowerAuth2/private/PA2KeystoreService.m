/*
 * Copyright 2024 Wultra s.r.o.
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

#import "PA2KeystoreService.h"
#import "PA2PrivateMacros.h"
#import "PA2HttpClient.h"
#import "PA2GetTemporaryKeyResponse.h"
#import <PowerAuth2/PowerAuthLog.h>

// We don't want to use the key that's close to its expiration on the server. This constant specifies for how much
// we move the expiration time to backward.
#define PUBLIC_KEY_EXPIRATION_THRESHOLD 10.0

#pragma mark - Service data

@interface PA2PublicKeyInfo : NSObject

- (instancetype) initWithScope:(PowerAuthCoreEciesEncryptorScope)scope;

@property (nonatomic, readonly) PowerAuthCoreEciesEncryptorScope scope;
@property (nonatomic, strong) PA2GetTemporaryKeyTask * task;
@property (nonatomic, assign) NSTimeInterval expiration;
@property (nonatomic, strong) id timeSynchronizationTask;

- (void) clearTask;

@end

#pragma mark - Service implementation

@implementation PA2KeystoreService
{
    id<PA2SessionInterface> _sessionInterface;
    id<PowerAuthCoreTimeService> _timeService;
    id<NSLocking> _lock;
    PA2HttpClient * _httpClient;
    NSString * _applicationKey;
    NSData * _deviceRelatedKey;

    PA2PublicKeyInfo * _pkiAppScope;
    PA2PublicKeyInfo * _pkiActScope;
}

- (instancetype) initWithHttpClient:(PA2HttpClient*)httpClient
                        timeService:(id<PowerAuthCoreTimeService>)timeService
                   deviceRelatedKey:(NSData*)deviceRelatedKey
                       sessionSetup:(PowerAuthCoreSessionSetup*)sessionSetup
                         sharedLock:(id<NSLocking>)sharedLock
{
    self = [super init];
    if (self) {
        _sessionInterface = httpClient.sessionInterface;
        _timeService = timeService;
        _httpClient = httpClient;
        _lock = sharedLock;
        _applicationKey = sessionSetup.applicationKey;
        _deviceRelatedKey = deviceRelatedKey;
        _pkiAppScope = [[PA2PublicKeyInfo alloc] initWithScope:PowerAuthCoreEciesEncryptorScope_Application];
        _pkiActScope = [[PA2PublicKeyInfo alloc] initWithScope:PowerAuthCoreEciesEncryptorScope_Activation];
    }
    return self;
}

- (id<PowerAuthOperationTask>) createKeyForEncryptorScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope callback:(void (^)(NSError *))callback
{
    if (encryptorScope == PowerAuthCoreEciesEncryptorScope_Activation && ![self hasValidActivation]) {
        callback(PA2MakeError(PowerAuthErrorCode_MissingActivation, nil));
        return nil;
    }
    
    [_lock lock];
    id<PowerAuthOperationTask> task = nil;
    if ([self hasKeyForEncryptorScope:encryptorScope]) {
        // Key already exist
        callback(nil);
    } else {
        // Key must be received from the server
        PA2PublicKeyInfo * pki = [self pkiForScope:encryptorScope];
        PA2GetTemporaryKeyTask * mainTask = pki.task;
        if (!mainTask) {
            mainTask = [[PA2GetTemporaryKeyTask alloc] initWithHttpClient:_httpClient
                                                          sessionProvider:_sessionInterface
                                                               sharedLock:_lock
                                                           applicationKey:_applicationKey
                                                         deviceRelatedKey:_deviceRelatedKey
                                                           encryptorScope:encryptorScope
                                                                 delegate:self];
            pki.task = mainTask;
            pki.timeSynchronizationTask = [_timeService startTimeSynchronizationTask];
        }
        task = [mainTask createChildTask:^(PA2GetTemporaryKeyResponse * _Nullable result, NSError * _Nullable error) {
            callback(error);
        }];
    }
    [_lock unlock];
    return task;
}

- (PA2PublicKeyInfo*) pkiForScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope
{
    return encryptorScope == PowerAuthCoreEciesEncryptorScope_Application ? _pkiAppScope : _pkiActScope;
}

- (BOOL) hasKeyForEncryptorScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope
{
    // This function is using access to two separately locked sections. The goal is to do not
    // overlap the critical sections. So, we have to query information in two separate steps.
    BOOL keyIsExpired;
    BOOL keyIsSet;
    
    [_lock lock];
    PA2PublicKeyInfo * pki = [self pkiForScope:encryptorScope];
    NSTimeInterval expiration = pki.expiration;
    keyIsSet = expiration >= 0.0;
    keyIsExpired = [_timeService currentTime] >= expiration - PUBLIC_KEY_EXPIRATION_THRESHOLD;
    if (keyIsExpired) {
        pki.expiration = -1;
    }
    [_lock unlock];
    
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        BOOL hasKey = [session hasPublicKeyForEciesScope:encryptorScope];
        if (hasKey && keyIsExpired && keyIsSet) {
            PowerAuthLog(@"Removing expired public key for ECIES encryptor %d", encryptorScope);
            [session removePublicKeyForEciesScope:encryptorScope];
            hasKey = NO;
        }
        return hasKey;
    }];
}

#pragma mark - PA2GetTemporaryKeyTaskDelegate

- (void) getTemporaryKeyTask:(PA2GetTemporaryKeyTask *)task didFinishWithResponse:(PA2GetTemporaryKeyResponse *)response error:(NSError *)error
{
    // [_lock lock] is guaranteed, because this method is called from task's completion while locked with shared lock.
    // So, we can freely mutate objects in this instance.
    PowerAuthCoreEciesEncryptorScope scope = task.encryptorScope;
    PA2PublicKeyInfo * pki = [self pkiForScope:scope];
    if (pki.task == task) {
        if (response) {
            NSTimeInterval receivedServerTime = 0.001 * (NSTimeInterval)response.serverTime;
            [_timeService completeTimeSynchronizationTask:pki.timeSynchronizationTask withServerTime:receivedServerTime];
            [self updatePublicKeyForEncryptorScope:scope withResponse:response];
        }
        [pki clearTask];
    }
}

- (BOOL) updatePublicKeyForEncryptorScope:(PowerAuthCoreEciesEncryptorScope)encryptorScope withResponse:(PA2GetTemporaryKeyResponse*)response
{
    BOOL success = [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        PowerAuthCoreErrorCode ec = [session setPublicKeyForEciesScope:encryptorScope publicKey:response.publicKey publicKeyId:response.keyId];
        if (ec != PowerAuthCoreErrorCode_Ok) {
            PowerAuthLog(@"Failed to update public key for ECIES encryption. Code = %d", ec);
            return NO;
        }
        return YES;
    }];
    if (success) {
        PA2PublicKeyInfo * pki = [self pkiForScope:encryptorScope];
        pki.expiration = 0.001 * response.expiration;
        PowerAuthLog(@"Saving public key for ECIES encryptor %d", encryptorScope);
    }
    return success;
}


#pragma mark - Support functions

- (BOOL) hasValidActivation
{
    return [[_sessionInterface readTaskWithSession:^id _Nullable(PowerAuthCoreSession * session) {
        return @([session hasValidActivation]);
    }] boolValue];
}

@end


@implementation PA2PublicKeyInfo

- (instancetype) initWithScope:(PowerAuthCoreEciesEncryptorScope)scope
{
    self = [super init];
    if (self) {
        _scope = scope;
    }
    return self;
}

- (void) clearTask
{
    _task = nil;
    _timeSynchronizationTask = nil;
}

@end
