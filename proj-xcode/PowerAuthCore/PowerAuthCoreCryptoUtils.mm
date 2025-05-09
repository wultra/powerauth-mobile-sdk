/**
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

#import <cc7/objc/ObjcHelper.h>     // must be first included
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>
#import "PowerAuthCorePrivateImpl.h"


using namespace io::getlime::powerAuth;

#pragma mark - Private interfaces -

@interface PowerAuthCoreECPublicKey (Private)
- (id) initWithEcKey:(const cc7::crypto::PublicKeyPtr&)ecKeyRef;
@property (nonatomic, readonly) const cc7::crypto::PublicKeyPtr & ecKeyRef;
@end

@interface PowerAuthCoreECPrivateKey (Private)
- (id) initWithEcKey:(const cc7::crypto::PrivateKeyPtr&)ecKeyRef;
@property (nonatomic, readonly) const cc7::crypto::PrivateKeyPtr & ecKeyRef;
@end

#pragma mark -

@implementation PowerAuthCoreCryptoUtils

+ (BOOL) ecdsaValidateSignature:(NSData *)signature
                        forData:(NSData *)data
                   forPublicKey:(PowerAuthCoreECPublicKey *)publicKey
{
    try {
        auto cpp_data = cc7::objc::CopyFromNSData(data);
        auto cpp_signature = cc7::objc::CopyFromNSData(signature);
        return (BOOL) cc7::crypto::Signature::getInstance("ECDSA-SHA-256")->verify(*publicKey.ecKeyRef, cpp_signature, cpp_data);
    } catch (std::exception & e) {
        return NO;
    }
}

+ (nullable NSData*) ecdsaComputeSignature:(nonnull NSData*)data
                            withPrivateKey:(nonnull PowerAuthCoreECPrivateKey*)privateKey
{
    try {
        auto cpp_data = cc7::objc::CopyFromNSData(data);
        auto cpp_signature = cc7::crypto::Signature::getInstance("ECDSA-SHA-256")->sign(*privateKey.ecKeyRef, cpp_data);
        return cc7::objc::CopyToNSData(cpp_signature);
    } catch (std::exception & e) {
        return nil;
    }
}

+ (nullable PowerAuthCoreData*) ecdhComputeSharedSecret:(nonnull PowerAuthCoreECPublicKey*)publicKey
                                         withPrivateKey:(nonnull PowerAuthCoreECPrivateKey*)privateKey
{
    try {
        auto secret = cc7::crypto::KeyAgreement::getInstance("ECDH")->phase(*privateKey.ecKeyRef, *publicKey.ecKeyRef);
        return [[PowerAuthCoreData alloc] initWithByteRange:secret->getKeyData()];
    } catch (std::exception & e) {
        return nil;
    }
}

+ (nullable PowerAuthCoreECKeyPair*) ecGenerateKeyPair
{
    try {
        auto key_pair = cc7::crypto::KeyPair::generateKeyPair("P-256");
        PowerAuthCoreECPublicKey * public_key = [[PowerAuthCoreECPublicKey alloc] initWithEcKey:key_pair->getPublicKeyPtr()];
        PowerAuthCoreECPrivateKey * private_key = [[PowerAuthCoreECPrivateKey alloc] initWithEcKey:key_pair->getPrivateKeyPtr()];
        return [[PowerAuthCoreECKeyPair alloc] initWithPrivateKey:private_key withPublicKey:public_key];
    } catch (std::exception & e) {
        return nil;
    }
}

+ (NSData*) hashSha256:(NSData *)data
{
    try {
        auto cpp_data = cc7::objc::CopyFromNSData(data);
        auto cpp_hash = cc7::crypto::MessageDigest::getInstance("SHA-256")->digest(cpp_data);
        return cc7::objc::CopyToNSData(cpp_hash);
    } catch (std::exception & e) {
        return nil;
    }
}


+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data 
                           key:(nonnull NSData*)key
{
    try {
        auto cpp_data = cc7::objc::CopyFromNSData(data);
        auto cpp_key = cc7::objc::CopyFromNSData(key);
        auto result = cc7::crypto::MAC::getInstance("HMAC-SHA-256")->token(cpp_key, cpp_data);
        return cc7::objc::CopyToNullableNSData(result);
    } catch (std::exception & e) {
        return nil;
    }
}


+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data
                           key:(nonnull NSData*)key
                        length:(NSUInteger)length
{
    try {
        auto cpp_data = cc7::objc::CopyFromNSData(data);
        auto cpp_key = cc7::objc::CopyFromNSData(key);
        auto result = cc7::crypto::MAC::getInstance("HMAC-SHA-256")->token(cpp_key, cpp_data, {
            { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take((size_t)length) }
        });
        return cc7::objc::CopyToNullableNSData(result);
    } catch (std::exception & e) {
        return nil;
    }
}


+ (nullable NSData*) randomBytes:(NSUInteger)count
{
    try {
        return cc7::objc::CopyToNullableNSData(cc7::crypto::GetRandomData(count, true));
    } catch (std::exception & e) {
        return nil;
    }
}

+ (nullable PowerAuthCoreData*) randomCoreData:(NSUInteger)count
{
    try {
        return [[PowerAuthCoreData alloc] initWithByteRange:cc7::crypto::GetRandomData(count, true)];
    } catch (std::exception & e) {
        return nil;
    }
}

@end



#pragma mark -

@implementation PowerAuthCoreECPublicKey
{
    cc7::crypto::PublicKeyPtr _key;
}

- (id) initWithEcKey:(const cc7::crypto::PublicKeyPtr &)ecKeyRef
{
    self = [super init];
    if (self) {
        _key = ecKeyRef;
    }
    return self;

}

- (id) initWithData:(NSData *)publicKeyData
{
    self = [super init];
    if (self) {
        try {
            _key = cc7::crypto::KeyPairFactory::getInstance("P-256")->newPublicKey(cc7::objc::CopyFromNSData(publicKeyData), cc7::crypto::KEY_FORMAT_X963);
        } catch (std::exception & e) {
            return nil;
        }
    }
    return self;
}

- (const cc7::crypto::PublicKeyPtr&) ecKeyRef
{
    return _key;
}

- (NSData*) publicKeyBytes
{
    try {
        return cc7::objc::CopyToNSData(_key->exportKey(cc7::crypto::KEY_FORMAT_X963));
    } catch (std::exception & e) {
        return nil;
    }
}

@end


#pragma mark -

@implementation PowerAuthCoreECPrivateKey
{
    cc7::crypto::PrivateKeyPtr _key;
}

- (id) initWithEcKey:(const cc7::crypto::PrivateKeyPtr &)ecKeyRef
{
    self = [super init];
    if (self) {
        _key = ecKeyRef;
    }
    return self;

}

- (id) initWithData:(NSData *)privateKeyData
{
    self = [super init];
    if (self) {
        try {
            _key = cc7::crypto::KeyPairFactory::getInstance("P-256")->newPrivateKey(cc7::objc::CopyFromNSData(privateKeyData), cc7::crypto::KEY_FORMAT_RAW);
        } catch (std::exception & e) {
            return nil;
        }
    }
    return self;
}

- (const cc7::crypto::PrivateKeyPtr&) ecKeyRef
{
    return _key;
}

- (NSData*) privateKeyBytes
{
    try {
        return cc7::objc::CopyToNSData(_key->exportKey(cc7::crypto::KEY_FORMAT_RAW));
    } catch (std::exception & e) {
        return nil;
    }
}

@end

#pragma mark -

@implementation PowerAuthCoreECKeyPair

- (instancetype) initWithPrivateKey:(PowerAuthCoreECPrivateKey *)privateKey
                      withPublicKey:(PowerAuthCoreECPublicKey *)publicKey
{
    self = [super init];
    if (self) {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }
    return self;
}

@end
