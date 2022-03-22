/*
 * Copyright 2022 Wultra s.r.o.
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

#pragma once

#include <cc7/jni/JniHelper.h>
#include <PowerAuth/crypto/CryptoUtils.h>
#include <openssl/ec.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace jni
{
	/**
	 * Object that contains reference to private EC_KEY.
	 */
	class EcPrivateKeyJNI {
	public:
		/**
		 * Create new instance of EcPrivateKeyJNI from provided private key data. Function returns
		 * nullptr if provided data doesn't represent private key.
		 */
		static EcPrivateKeyJNI * createFromBytes(const cc7::ByteRange & private_key_data, BN_CTX * ctx = nullptr) {
			auto ec_key = crypto::ECC_ImportPrivateKey(nullptr, private_key_data, ctx);
			return ec_key != nullptr ? new EcPrivateKeyJNI(ec_key) : nullptr;
		}

		~EcPrivateKeyJNI() {
			EC_KEY_free(ec_key);
		}

		/**
		 * Return private key bytes. If empty array is returned, then this object doesn't
		 * have valid private key.
		 */
		cc7::ByteArray privateKeyBytes() const {
			return crypto::ECC_ExportPrivateKey(ec_key);
		}

		/**
		 * Return pointer to private key implementation.
		 */
		EC_KEY * keyPtr() const {
			return ec_key;
		}

	private:

		EcPrivateKeyJNI(EC_KEY * ec_key) : ec_key(ec_key) {}

		EC_KEY * ec_key;
	};
	
} // io::getlime::powerAuth::jni
} // io::getlime::powerAuth
} // io::getlime
} // io

/**
 * Get CPP object from EcPrivateKey java object.
 */
CC7_EXTERN_C io::getlime::powerAuth::jni::EcPrivateKeyJNI * GetEcPrivateKeyFromJavaObject(JNIEnv * env, jobject object);

/**
 * Create EcPrivateKey java object from provided CPP object. If object creation fails, then CPP object is destroyed.
 */
CC7_EXTERN_C jobject CreateJavaEcPrivateKeyFromCppObject(JNIEnv * env, io::getlime::powerAuth::jni::EcPrivateKeyJNI * object);
