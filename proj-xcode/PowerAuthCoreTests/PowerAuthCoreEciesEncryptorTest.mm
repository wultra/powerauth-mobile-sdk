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

#import <XCTest/XCTest.h>
#import <PowerAuthCore/PowerAuthCore.h>

#include <PowerAuth/PowerAuth.h>
#include <cc7/objc/ObjcHelper.h>
#include <stdlib.h>

#import "PowerAuthCorePrivateImpl.h"

#define PRINT_JSON  0
#define PRINT_JAVA  1

#if PRINT_JAVA
#define TestGen _TestGen
#else
#define TestGen(arg...)
#endif

// Print message to stdout without an usual prefix added by NSLog.
static void _TestGen(NSString * format, ...)
{
    va_list args;
    va_start(args, format);
    NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    fputs(message.UTF8String, stdout);
    fputc('\n', stdout);
}

/**
 This unit test generates test vectors for our ECIES scheme. The test vectors can be then
 used in backend Java Unit tests. The test supports two formats:
 - Java code snippet (set PRINT_JAVA macro to 1)
 - JSON format (set PRINT_JSON macro to 1)
 */
@interface PowerAuthCoreEciesEncryptorTest : XCTestCase
@end

@implementation PowerAuthCoreEciesEncryptorTest
{
    PowerAuthCoreECKeyPair * _masterKeyPair;
    PowerAuthCoreECKeyPair * _serverKeyPair;
    NSString * _appKey;
    NSString * _appSecret;
    NSData * _transportKey;
    NSString * _activationId;
    NSArray * _sharedInfo1Values;
    NSUInteger _sharedInfo1Index;
    
    io::getlime::powerAuth::ECIESDecryptor _decryptor;
}

- (void) setUp
{
    [super setUp];
    
    _masterKeyPair = [PowerAuthCoreCryptoUtils ecGenerateKeyPair];
    _serverKeyPair = [PowerAuthCoreCryptoUtils ecGenerateKeyPair];
    _appKey = [[PowerAuthCoreCryptoUtils randomBytes:16] base64EncodedStringWithOptions:0];
    _appSecret = [[PowerAuthCoreCryptoUtils randomBytes:16] base64EncodedStringWithOptions:0];
    _transportKey = [PowerAuthCoreCryptoUtils randomBytes:16];
    _activationId = [[NSUUID UUID] UUIDString];
    _sharedInfo1Values = @[
        @[@"/pa/generic/application",   @"APPLICATION_SCOPE_GENERIC"],
        @[@"/pa/generic/activation",    @"ACTIVATION_SCOPE_GENERIC"],
        @[@"/pa/activation",            @"ACTIVATION_LAYER_2"],
        @[@"/pa/upgrade",               @"UPGRADE"],
        @[@"/pa/vault/unlock",          @"VAULT_UNLOCK"],
        @[@"/pa/token/create",          @"CREATE_TOKEN"],
        @[@"/pa/recovery/confirm",      @"CONFIRM_RECOVERY_CODE"]
    ];
}

- (void) testGenerateEciesTestVectors
{
    NSMutableDictionary * td = [NSMutableDictionary dictionary];
    NSMutableArray * tda = [NSMutableArray array];
    NSMutableArray * arrRequests = [NSMutableArray array];
    NSMutableArray * arrResponses = [NSMutableArray array];
    NSMutableArray * arrScopes = [NSMutableArray array];
    NSMutableArray * arrSharedInfo1s = [NSMutableArray array];
    NSMutableArray * arrEncryptedRequests = [NSMutableArray array];
    NSMutableArray * arrEncryptedResponses = [NSMutableArray array];
    
    td[@"configuration"] = @{
        @"keyMasterPrivate": [_masterKeyPair.privateKey.privateKeyBytes base64EncodedStringWithOptions:0],
        @"keyMasterPublic": [_masterKeyPair.publicKey.publicKeyBytes base64EncodedStringWithOptions:0],
        @"keyServerPrivate": [_serverKeyPair.privateKey.privateKeyBytes base64EncodedStringWithOptions:0],
        @"keyServerPublic": [_serverKeyPair.publicKey.publicKeyBytes base64EncodedStringWithOptions:0],
        @"applicationKey": _appKey,
        @"applicationSecret": _appSecret,
        @"transportKey": [_transportKey base64EncodedStringWithOptions:0],
        @"activationId": _activationId
    };
    td[@"testData"] = tda;
    for (int i = 0; i < 16; i++) {
        BOOL appScope = (i & 1) == 1;
        NSString * scope = appScope ? @"application" : @"activation";
        NSData * requestData = [self randomData];
        NSData * responseData = [self randomData];
        NSArray * sh1 = [self pickSharedInfo1];
        NSString * sharedInfo1 = sh1[0];
        NSString * sharedInfo1Enum = sh1[1];
        PowerAuthCoreEciesEncryptor * encryptor = [self createEncryptor:appScope sh1:sharedInfo1];
        PowerAuthCoreEciesCryptogram * request = [encryptor encryptRequest:requestData];
        XCTAssertNotNil(request.key);
        XCTAssertNotNil(request.body);
        XCTAssertNotNil(request.mac);
        XCTAssertNotNil(request.nonce);

        NSData * associatedData = cc7::objc::CopyToNSData(encryptor.associatedMetaData.associatedData);
        // Try to decrypt response
        NSData * decryptedRequestData = [self decryptRequest:request sh1:sharedInfo1 associatedData:associatedData appScope:appScope];
        XCTAssertNotNil(decryptedRequestData);
        XCTAssertEqualObjects(requestData, decryptedRequestData);
        // Encrypt response
        PowerAuthCoreEciesCryptogram * response = [self encryptResponse:responseData sh1:sharedInfo1 associatedData:associatedData appScope:appScope];
        
        // And try to decrypt the response data
        NSData * decryptedResponseData = [encryptor decryptResponse:response];
        XCTAssertNotNil(decryptedResponseData);
        XCTAssertEqualObjects(responseData, decryptedResponseData);
        
        [arrRequests addObject:[requestData base64EncodedStringWithOptions:0]];
        [arrResponses addObject:[responseData base64EncodedStringWithOptions:0]];
        [arrSharedInfo1s addObject:sharedInfo1Enum];
        [arrScopes addObject:@(appScope)];
        NSDictionary * req = @{
            @"ephemeralPublicKey": request.keyBase64,
            @"encryptedData": request.bodyBase64,
            @"mac": request.macBase64,
            @"nonce": request.nonceBase64,
            @"timestamp": @(request.timestamp)
        };
        NSDictionary * resp = @{
            @"encryptedData": response.bodyBase64,
            @"mac": response.macBase64,
            @"nonce": response.nonceBase64,
            @"timestamp": @(response.timestamp)
        };
        [arrEncryptedRequests addObject:req];
        [arrEncryptedResponses addObject:resp];
        
        [tda addObject:@{
            @"input": @{
                @"scope": scope,
                @"plaintextRequestData": [requestData base64EncodedStringWithOptions:0],
                @"plaintextResponseData": [responseData base64EncodedStringWithOptions:0],
                @"sharedInfo1": sharedInfo1
            },
            @"request": req,
            @"response": resp
        }];
    }
    TestGen(@"Generating code snippet for Java tests...");
    TestGen(@"-----------------------");
    // Print generated data as Java function snippet.
    TestGen(@"");
    TestGen(@"// Shared constants");
    TestGen(@"final PrivateKey masterServerPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode(\"%@\")));", td[@"configuration"][@"keyMasterPrivate"]);
    TestGen(@"final PublicKey masterServerPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(\"%@\"));", td[@"configuration"][@"keyMasterPublic"]);
    TestGen(@"final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode(\"%@\")));", td[@"configuration"][@"keyServerPrivate"]);
    TestGen(@"final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(\"%@\"));", td[@"configuration"][@"keyServerPublic"]);
    TestGen(@"final String activationId = \"%@\";", _activationId);
    TestGen(@"final String applicationKey = \"%@\";", _appKey);
    TestGen(@"final String applicationSecret = \"%@\";", _appSecret);
    TestGen(@"final byte[] transportKey = Base64.getDecoder().decode(\"%@\");", [_transportKey base64EncodedStringWithOptions:0]);
    TestGen(@"// associated data");
    TestGen(@"final byte[] adApplicationScope = deriveAssociatedData(EciesScope.APPLICATION_SCOPE, \"3.2\", applicationKey, null);");
    TestGen(@"final byte[] adActivationScope = deriveAssociatedData(EciesScope.ACTIVATION_SCOPE, \"3.2\", applicationKey, activationId);");
    TestGen(@"// Original request data");
    TestGen(@"final byte[][] plainRequestData = {");
    [arrRequests enumerateObjectsUsingBlock:^(NSString * data, NSUInteger idx, BOOL * _Nonnull stop) {
        TestGen(@"    Base64.getDecoder().decode(\"%@\"),", data);
    }];
    TestGen(@"};");
    TestGen(@"// Original response data");
    TestGen(@"final byte[][] plainResponseData = {");
    [arrResponses enumerateObjectsUsingBlock:^(NSString * data, NSUInteger idx, BOOL * _Nonnull stop) {
        TestGen(@"    Base64.getDecoder().decode(\"%@\"),", data);
    }];
    TestGen(@"};");
    TestGen(@"// SharedInfo1s");
    TestGen(@"final EciesSharedInfo1[] sharedInfo1 = {");
    [arrSharedInfo1s enumerateObjectsUsingBlock:^(NSString * info, NSUInteger idx, BOOL * _Nonnull stop) {
        TestGen(@"    EciesSharedInfo1.%@,", info);
    }];
    TestGen(@"};");
    TestGen(@"// Scopes");
    TestGen(@"final EciesScope[] scopes = {");
    [arrScopes enumerateObjectsUsingBlock:^(NSNumber * scope, NSUInteger idx, BOOL * _Nonnull stop) {
        TestGen(@"    EciesScope.%@,", [scope boolValue] ? @"APPLICATION_SCOPE" : @"ACTIVATION_SCOPE");
    }];
    TestGen(@"};");
    TestGen(@"// Requests");
    TestGen(@"final EciesPayload[] encryptedRequest = {");
    [arrEncryptedRequests enumerateObjectsUsingBlock:^(NSDictionary * obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString * scopeAdVar = [arrScopes[idx] boolValue] ? @"adApplicationScope" : @"adActivationScope";
        TestGen(@"    new EciesPayload(");
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"ephemeralPublicKey"]);
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"mac"]);
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"encryptedData"]);
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"nonce"]);
        TestGen(@"        %@,", scopeAdVar);
        TestGen(@"        %@L", obj[@"timestamp"]);
        TestGen(@"    ),");
    }];
    TestGen(@"};");
    TestGen(@"// Responses");
    TestGen(@"final EciesPayload[] encryptedResponse = {");
    [arrEncryptedResponses enumerateObjectsUsingBlock:^(NSDictionary * obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString * scopeAdVar = [arrScopes[idx] boolValue] ? @"adApplicationScope" : @"adActivationScope";
        TestGen(@"    new EciesPayload(");
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", arrEncryptedRequests[idx][@"ephemeralPublicKey"]);    // pick ephemeral key from request, we don't keep it in response
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"mac"]);
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"encryptedData"]);
        TestGen(@"        Base64.getDecoder().decode(\"%@\"),", obj[@"nonce"]);
        TestGen(@"        %@,", scopeAdVar);
        TestGen(@"        %@L", obj[@"timestamp"]);
        TestGen(@"    ),");
    }];
    TestGen(@"};");
    TestGen(@"-----------------------");
    // Print generated data as JSON
#if PRINT_JSON
    NSData * jsonData = [NSJSONSerialization dataWithJSONObject:td options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    NSString * jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSLog(@"\n\nTest data:\n%@", jsonString);
#endif
}

- (NSData*) randomData
{
    return [PowerAuthCoreCryptoUtils randomBytes:3 + arc4random_uniform(128)];
}

- (NSArray*) pickSharedInfo1
{
    NSArray * sh1 = _sharedInfo1Values[_sharedInfo1Index];
    _sharedInfo1Index = (_sharedInfo1Index + 1) % _sharedInfo1Values.count;
    return sh1;
}

- (NSData*) sh2ForScope:(BOOL)appScope
{
    if (appScope) {
        return [PowerAuthCoreCryptoUtils hashSha256:[_appSecret dataUsingEncoding:NSUTF8StringEncoding]];
    } else {
        return [PowerAuthCoreCryptoUtils hmacSha256:[_appSecret dataUsingEncoding:NSUTF8StringEncoding] key:_transportKey];
    }
}

- (PowerAuthCoreEciesEncryptor*) createEncryptor:(BOOL)appScope sh1:(NSString*)sh1
{
    NSData * publicKeyBytes = appScope ? _masterKeyPair.publicKey.publicKeyBytes : _serverKeyPair.publicKey.publicKeyBytes;
    NSData * sharedInfo1 = [sh1 dataUsingEncoding:NSUTF8StringEncoding];
    NSData * sharedInfo2 = [self sh2ForScope:appScope];
    NSString * activationId = appScope ? nil : _activationId;
    PowerAuthCoreEciesEncryptor * encryptor = [[PowerAuthCoreEciesEncryptor alloc] initWithPublicKey:publicKeyBytes sharedInfo1:sharedInfo1 sharedInfo2:sharedInfo2];
    encryptor.associatedMetaData = [[PowerAuthCoreEciesMetaData alloc] initWithApplicationKey:_appKey activationIdentifier:activationId];
    return encryptor;
}

- (NSData*) decryptRequest:(PowerAuthCoreEciesCryptogram*)cryptogram sh1:(NSString*)sh1 associatedData:(NSData*)associatedData appScope:(BOOL)appScope
{
    // Initialize decryptor
    NSData * privateKeyBytes = appScope ? _masterKeyPair.privateKey.privateKeyBytes : _serverKeyPair.privateKey.privateKeyBytes;
    auto privateKey = cc7::objc::CopyFromNSData(privateKeyBytes);
    auto sharedInfo1 = cc7::objc::CopyFromNSStringToByteArray(sh1);
    auto sharedInfo2 = cc7::objc::CopyFromNSData([self sh2ForScope:appScope]);
    _decryptor = io::getlime::powerAuth::ECIESDecryptor(privateKey, sharedInfo1, sharedInfo2);
    
    io::getlime::powerAuth::ECIESCryptogram cppCryptogram;
    cppCryptogram.key = cc7::objc::CopyFromNSData(cryptogram.key);
    cppCryptogram.body = cc7::objc::CopyFromNSData(cryptogram.body);
    cppCryptogram.nonce = cc7::objc::CopyFromNSData(cryptogram.nonce);
    cppCryptogram.mac = cc7::objc::CopyFromNSData(cryptogram.mac);
    
    io::getlime::powerAuth::ECIESParameters cppParams;
    cppParams.timestamp = cryptogram.timestamp;
    cppParams.associatedData = cc7::objc::CopyFromNSData(associatedData);
    
    cc7::ByteArray decrypted;
    auto ec = _decryptor.decryptRequest(cppCryptogram, cppParams, decrypted);
    if (ec == io::getlime::powerAuth::EC_Ok) {
        return cc7::objc::CopyToNSData(decrypted);
    }
    NSLog(@"Decryptor [decrypt] failed with code %@", @(ec));
    return nil;
}

- (PowerAuthCoreEciesCryptogram*) encryptResponse:(NSData*)responseData sh1:(NSString*)sh1 associatedData:(NSData*)associatedData appScope:(BOOL)appScope
{
    io::getlime::powerAuth::ECIESCryptogram cppCryptogram;
    io::getlime::powerAuth::ECIESParameters cppParams;
    cppParams.timestamp = (cc7::U64)([[PowerAuthCoreTimeService sharedInstance] currentTime] * 1000.0);
    cppParams.associatedData = cc7::objc::CopyFromNSData(associatedData);
    auto ec = _decryptor.encryptResponse(cc7::objc::CopyFromNSData(responseData), cppParams, cppCryptogram);
    if (ec == io::getlime::powerAuth::EC_Ok) {
        PowerAuthCoreEciesCryptogram * cryptogram = [[PowerAuthCoreEciesCryptogram alloc] init];
        cryptogram.timestamp = cppParams.timestamp;
        cryptogram.body = cc7::objc::CopyToNSData(cppCryptogram.body);
        cryptogram.mac = cc7::objc::CopyToNSData(cppCryptogram.mac);
        cryptogram.nonce = cc7::objc::CopyToNSData(cppCryptogram.nonce);
        return cryptogram;
    }
    NSLog(@"Decryptor [encrypt] failed with code %@", @(ec));
    return nil;
}

@end
