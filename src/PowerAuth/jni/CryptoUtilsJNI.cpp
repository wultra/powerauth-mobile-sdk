/*
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

#include <cc7/jni/JniHelper.h>
#include "../crypto/CryptoUtils.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH	    	"io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE	    io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS  		CryptoUtils
#define CC7_JNI_CPP_CLASS		    NA
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

extern "C" {

//
// public static native byte[] ecdsaValidateSignature(byte[] data, byte[] signature, byte[] publicKeyData)
//
CC7_JNI_METHOD_PARAMS(jboolean, ecdsaValidateSignature, jbyteArray data, jbyteArray signature, jbyteArray publicKeyData)
{
	if (data == nullptr || signature == nullptr || publicKeyData == nullptr || env == nullptr) {
		CC7_ASSERT(false, "Missing required parameter.");
		return false;
	}

	bool result = false;

	// Convert data objects
	auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
	auto cpp_signature = cc7::jni::CopyFromJavaByteArray(env, signature);
	auto cpp_publicKey = cc7::jni::CopyFromJavaByteArray(env, publicKeyData);

	// Import EC public key
	EC_KEY * ec_key = crypto::ECC_ImportPublicKey(nullptr, cpp_publicKey);
	if (CC7_CHECK(ec_key != nullptr, "Cannot import EC public key.")) {
		// Validate signature
		result = crypto::ECDSA_ValidateSignature(cpp_data, cpp_signature, ec_key);
		// Cleanup imported key
		EC_KEY_free(ec_key);
	}
	return result;
}


//
// public static native byte[] hashSha256(byte[] data)
//
CC7_JNI_METHOD_PARAMS(jbyteArray, hashSha256, jbyteArray data)
{
	if (data == nullptr || env == nullptr) {
		CC7_ASSERT(false, "Missing required parameter.");
		return nullptr;
	}

	// Convert data objects & calculate hash
	auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
	auto hash = crypto::SHA256(cpp_data);
	return cc7::jni::CopyToJavaByteArray(env, hash);
}

//
// public static native byte[] hmacSha256(byte[] data, byte[] key, int outputLength)
//
CC7_JNI_METHOD_PARAMS(jbyteArray, hmacSha256, jbyteArray data, jbyteArray key, jint outputLength)
{
	if (data == nullptr || key == nullptr || env == nullptr) {
		CC7_ASSERT(false, "Missing required parameter.");
		return nullptr;
	}
	if (outputLength < 0) {
		CC7_ASSERT(false, "Invalid 'outputLength' parameter.");
		return nullptr;
	}
	// Convert data objects
	auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
	auto cpp_key = cc7::jni::CopyFromJavaByteArray(env, key);
	auto mac = crypto::HMAC_SHA256(cpp_data, cpp_key, (size_t)outputLength);
	return cc7::jni::CopyToJavaByteArray(env, mac);
}

//
// public static native byte[] randomBytes(int count);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, randomBytes, jint count)
{
	if (env == nullptr) {
		CC7_ASSERT(false, "Missing required parameter.");
		return nullptr;
	}
	if (count < 0) {
		CC7_ASSERT(false, "Invalid 'count' parameter.");
		return nullptr;
	}
	// Generate random data
	auto random_bytes = crypto::GetRandomData((size_t)count, true);
	return cc7::jni::CopyToNullableJavaByteArray(env, random_bytes);
}

} // extern "C"
