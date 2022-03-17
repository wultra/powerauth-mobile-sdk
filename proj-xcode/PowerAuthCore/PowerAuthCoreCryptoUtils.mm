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

#import <cc7/objc/ObjcHelper.h>		// must be first included
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>
#include "CryptoUtils.h"			// Accessing private header; will be fixed by moving crypto to cc7


using namespace io::getlime::powerAuth;

#pragma mark - Private interfaces -

@interface PowerAuthCoreECPublicKey (Private)
@property (nonatomic, readonly) EC_KEY * ecKeyRef;
@end

@interface PowerAuthCoreECPrivateKey (Private)
@property (nonatomic, readonly) EC_KEY * ecKeyRef;
@end

#pragma mark -

@implementation PowerAuthCoreCryptoUtils

+ (BOOL) ecdsaValidateSignature:(NSData *)signature
						forData:(NSData *)data
				   forPublicKey:(PowerAuthCoreECPublicKey *)publicKey
{
	auto cpp_data = cc7::objc::CopyFromNSData(data);
	auto cpp_signature = cc7::objc::CopyFromNSData(signature);
	return (BOOL) crypto::ECDSA_ValidateSignature(cpp_data, cpp_signature, publicKey.ecKeyRef);
}

+ (nullable NSData*) ecdsaComputeSignature:(nonnull NSData*)data
                            withPrivateKey:(nonnull PowerAuthCoreECPrivateKey*)privateKey
{
    auto cpp_data = cc7::objc::CopyFromNSData(data);
    cc7::ByteArray cpp_signature;
    if (crypto::ECDSA_ComputeSignature(cpp_data, privateKey.ecKeyRef, cpp_signature)) {
        return cc7::objc::CopyToNSData(cpp_signature);
    }
    return nil;
}

+ (nullable NSData*) ecdhComputeSharedSecret:(nonnull PowerAuthCoreECPublicKey*)publicKey
                              withPrivateKey:(nonnull PowerAuthCoreECPrivateKey*)privateKey
{
    auto shared_secret = crypto::ECDH_SharedSecret(publicKey.ecKeyRef, privateKey.ecKeyRef);
    if (shared_secret.empty()) {
        return nil;
    }
    return cc7::objc::CopyToNSData(shared_secret);
}

+ (nullable PowerAuthCoreECKeyPair*) ecGenerateKeyPair
{
    EC_KEY * key_pair = crypto::ECC_GenerateKeyPair();
    if (key_pair == nullptr) {
        return nil;
    }
    crypto::BNContext context;
    auto public_key_bytes = crypto::ECC_ExportPublicKey(key_pair, context);
    auto private_key_bytes = crypto::ECC_ExportPrivateKey(key_pair, context);
    if (public_key_bytes.empty() || private_key_bytes.empty()) {
        return nil;
    }
    PowerAuthCoreECPublicKey * public_key = [[PowerAuthCoreECPublicKey alloc] initWithData:cc7::objc::CopyToNSData(public_key_bytes)];
    PowerAuthCoreECPrivateKey * private_key = [[PowerAuthCoreECPrivateKey alloc] initWithData:cc7::objc::CopyToNSData(private_key_bytes)];
    return [[PowerAuthCoreECKeyPair alloc] initWithPrivateKey:private_key withPublicKey:public_key];
}

+ (NSData*) hashSha256:(NSData *)data
{
	auto cpp_data = cc7::objc::CopyFromNSData(data);
	auto cpp_hash = crypto::SHA256(cpp_data);
	return cc7::objc::CopyToNSData(cpp_hash);
}


+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data 
						   key:(nonnull NSData*)key
{
	auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), 0);
	return cc7::objc::CopyToNullableNSData(result);
}


+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data
						   key:(nonnull NSData*)key
						length:(NSUInteger)length
{
	auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), length);
	return cc7::objc::CopyToNullableNSData(result);
}


+ (nullable NSData*) randomBytes:(NSUInteger)count
{
	return cc7::objc::CopyToNullableNSData(crypto::GetRandomData(count, true));
}

@end



#pragma mark -

@implementation PowerAuthCoreECPublicKey
{
	EC_KEY * _key;
}

- (void) dealloc
{
	EC_KEY_free(_key);
	_key = nullptr;
}

- (id) initWithData:(NSData *)publicKeyData
{
	self = [super init];
	if (self) {
		_key = crypto::ECC_ImportPublicKey(nullptr, cc7::objc::CopyFromNSData(publicKeyData));
		if (!_key) {
			return nil;
		}
	}
	return self;
}

- (EC_KEY*) ecKeyRef
{
	return _key;
}

- (NSData*) publicKeyBytes
{
    return cc7::objc::CopyToNSData(crypto::ECC_ExportPublicKey(_key));
}

@end


#pragma mark -

@implementation PowerAuthCoreECPrivateKey
{
    EC_KEY * _key;
}

- (void) dealloc
{
    EC_KEY_free(_key);
    _key = nullptr;
}

- (id) initWithData:(NSData *)privateKeyData
{
    self = [super init];
    if (self) {
        _key = crypto::ECC_ImportPrivateKey(nullptr, cc7::objc::CopyFromNSData(privateKeyData));
        if (!_key) {
            return nil;
        }
    }
    return self;
}

- (EC_KEY*) ecKeyRef
{
    return _key;
}

- (NSData*) privateKeyBytes
{
    return cc7::objc::CopyToNSData(crypto::ECC_ExportPrivateKey(_key));
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
