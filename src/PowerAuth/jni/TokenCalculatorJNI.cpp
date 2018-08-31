/*
 * Copyright 2017 Wultra s.r.o.
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
#include "../protocol/Constants.h"
#include <sys/time.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH	    	"io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE	    io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS  		TokenCalculator
#define CC7_JNI_CPP_CLASS		    NA
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

extern "C" {

/**
 This helper function returns milliseconds timestamps sice 1970 in string format.
 */
static std::string _GetTimestamp() 
{
	// Get timestamp...
	struct timeval tv;
	gettimeofday(&tv, NULL);

	// Calculate milliseconds since 1970
	double msSinceEpoch = (double)(tv.tv_sec) * 1000.0 + (double)(tv.tv_usec) * 0.001;

	// ...and convert that value to string (without decimal part)
	return std::to_string((uint64_t) msSinceEpoch);
}

//
// public static native String calculateTokenValue(PowerAuthPrivateTokenData tokenData)
//
CC7_JNI_METHOD_PARAMS(jstring, calculateTokenValue, jobject privateData)
{
	if (privateData == NULL || env == NULL) {
		CC7_ASSERT(false, "Missing parameter privateData.");
		return NULL;
	}
	// Look for io.getlime.security.powerauth.sdk.impl.PowerAuthPrivateTokenData
	jclass privateDataClazz = env->FindClass("io/getlime/security/powerauth/sdk/impl/PowerAuthPrivateTokenData");

	// Load parameters into C++ objects
	auto cppTokenSecret = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(privateData, privateDataClazz, "secret"));
	auto cppTokenIdentifier = cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(privateData, privateDataClazz, "identifier"));

	if (cppTokenSecret.size() != 16 || cppTokenIdentifier.empty()) {
		CC7_ASSERT(false, "PowerAuthPrivateTokenData is not valid.");
		return NULL;
	}

	// Get nonce & timestamp
	std::string timestamp = _GetTimestamp();
	cc7::ByteArray nonce = crypto::GetRandomData(16);

	// Construct data for HMAC and calculate that digest.
	cc7::ByteArray data;
	data.reserve(16 + 1 + timestamp.length());

	data.assign(nonce);
	data.append(cc7::MakeRange(protocol::AMP));
	data.append(cc7::MakeRange(timestamp));
	auto digest = crypto::HMAC_SHA256(data, cppTokenSecret, 0);
	if (digest.size() == 0) {
		CC7_ASSERT(false, "Unable to calculate HMAC for data.");
		return NULL;
	}

	// Construct header
	auto digestBase64 = digest.base64String();
	auto nonceBase64 = nonce.base64String();

	std::string result;
	result.reserve(cppTokenIdentifier.length() + digestBase64.length() + nonceBase64.length() + timestamp.length() + 80);

	result.assign("PowerAuth version=\"2.1\", token_id=\"");
	result.append(cppTokenIdentifier);
	result.append("\", token_digest=\"");
	result.append(digestBase64);
	result.append("\", nonce=\"");
	result.append(nonceBase64);
	result.append("\", timestamp=\"");
	result.append(timestamp);
	result.append("\"");

	return cc7::jni::CopyToJavaString(env, result);
}

} // extern "C"
