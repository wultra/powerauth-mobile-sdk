/**
 * Copyright 2018 Wultra s.r.o.
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
#import "PA2CryptoUtils.h"
#include "CryptoUtils.h"			// Accessing private header; will be fixed by moving crypto to cc7


using namespace io::getlime::powerAuth;

#pragma mark - Private interfaces -

@interface PA2ECPublicKey (Private)
@property (nonatomic, readonly) EC_KEY * ecKeyRef;
@end



#pragma mark -

@implementation PA2CryptoUtils

+ (BOOL) ecdsaValidateSignature:(NSData *)signature
						forData:(NSData *)data
				   forPublicKey:(PA2ECPublicKey *)publicKey
{
	auto cpp_data = cc7::objc::CopyFromNSData(data);
	auto cpp_signature = cc7::objc::CopyFromNSData(signature);
	return (BOOL) crypto::ECDSA_ValidateSignature(cpp_data, cpp_signature, publicKey.ecKeyRef);
}


+ (NSData*) hashSha256:(NSData *)data
{
	auto cpp_data = cc7::objc::CopyFromNSData(data);
	auto cpp_hash = crypto::SHA256(cpp_data);
	return cc7::objc::CopyToNSData(cpp_hash);
}

@end



#pragma mark -

@implementation PA2ECPublicKey
{
	EC_KEY * _key;
}

#pragma mark - Init & Dealloc

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

#pragma mark - Getters

- (EC_KEY*) ecKeyRef
{
	return _key;
}

@end
