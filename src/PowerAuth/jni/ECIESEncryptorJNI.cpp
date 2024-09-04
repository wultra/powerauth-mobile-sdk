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

#include "ECIESEncryptorJNI.h"
#include <cc7/Base64.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          EciesEncryptor
#define CC7_JNI_CPP_CLASS           ECIESEncryptor
#include <cc7/jni/JniModule.inl>

#include <android/log.h>

using namespace io::getlime::powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

jobject CreateJavaCryptogramFromCppObject(JNIEnv * env, const ECIESCryptogram & cryptogram, const ECIESParameters & parameters, const std::string & temporaryKeyId)
{
    if (!env) {
        CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
        return nullptr;
    }
    // Create EciesCryptogram java class instance
    jclass  resultClazz  = CC7_JNI_MODULE_FIND_CLASS("EciesCryptogram");
    jobject resultObject = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("EciesCryptogram"), "()V");
    if (!resultObject) {
        return nullptr;
    }
    // ...and setup fields
    CC7_JNI_SET_FIELD_BYTEARRAY(resultObject, resultClazz, "body", cc7::jni::CopyToNullableJavaByteArray(env, cryptogram.body));
    CC7_JNI_SET_FIELD_BYTEARRAY(resultObject, resultClazz, "mac",  cc7::jni::CopyToNullableJavaByteArray(env, cryptogram.mac));
    CC7_JNI_SET_FIELD_BYTEARRAY(resultObject, resultClazz, "key",  cc7::jni::CopyToNullableJavaByteArray(env, cryptogram.key));
    CC7_JNI_SET_FIELD_BYTEARRAY(resultObject, resultClazz, "nonce",  cc7::jni::CopyToNullableJavaByteArray(env, cryptogram.nonce));
    CC7_JNI_SET_FIELD_STRING(resultObject, resultClazz, "temporaryKeyId", cc7::jni::CopyToNullableJavaString(env, temporaryKeyId));
    CC7_JNI_SET_FIELD_LONG(resultObject, resultClazz, "timestamp",  (jlong) parameters.timestamp);
    return resultObject;
}

void LoadCppCryptogramFromJavaObject(JNIEnv * env, jobject cryptogram, ECIESCryptogram & cppCryptogram, ECIESParameters & cppParameters)
{
    jclass clazz  = CC7_JNI_MODULE_FIND_CLASS("EciesCryptogram");
    cppCryptogram.body  = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(cryptogram, clazz, "body"));
    cppCryptogram.mac   = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(cryptogram, clazz, "mac"));
    cppCryptogram.key   = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(cryptogram, clazz, "key"));
    cppCryptogram.nonce = cc7::jni::CopyFromJavaByteArray(env, CC7_JNI_GET_FIELD_BYTEARRAY(cryptogram, clazz, "nonce"));
    cppParameters.timestamp = (cc7::U64) CC7_JNI_GET_FIELD_LONG(cryptogram, clazz, "timestamp");
}

jobject CreateJavaEncryptorFromCppObject(JNIEnv * env, const ECIESEncryptor & encryptor, jobject timeService)
{
    if (!env) {
        CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
        return nullptr;
    }
    // Create ECIESEncryptor java class instance
    auto encryptor_copy = new ECIESEncryptor(encryptor);
    auto encryptor_copy_long = reinterpret_cast<jlong>(encryptor_copy);
    jobject resultObject = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("EciesEncryptor"), "(JLio/getlime/security/powerauth/core/ICoreTimeService;)V", encryptor_copy_long, timeService);
    if (nullptr == resultObject) {
        // If java object was not constructed then we delete the encryptor's copy.
        delete encryptor_copy;
    }
    return resultObject;
}

static cc7::ByteArray LoadAssociatedData(JNIEnv * env, jobject encryptor, std::string & out_temporary_key_id)
{
    if (!env) {
        CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
        return cc7::ByteArray();
    }
    // Get metaData object from the encryptor and create associated data
    jclass encryptorClazz = CC7_JNI_MODULE_FIND_CLASS("EciesEncryptor");
    jclass metaDataClazz = env->FindClass("io/getlime/security/powerauth/ecies/EciesMetadata");
    if (encryptorClazz == nullptr || metaDataClazz == nullptr) {
        CC7_ASSERT(false, "Missing required required classes.");
        return cc7::ByteArray();
    }
    jobject metaData = CC7_JNI_GET_FIELD_OBJECT(encryptor, encryptorClazz, "metadata", "Lio/getlime/security/powerauth/ecies/EciesMetadata;");
    if (metaData == nullptr) {
        CC7_ASSERT(false, "Missing metadata in encryptor.");
        return cc7::ByteArray();
    }
    // Extract parameters from EciesMetaData object
    out_temporary_key_id = cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(metaData, metaDataClazz, "temporaryKeyId"));
    auto applicationKey = cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(metaData, metaDataClazz, "applicationKey"));
    auto activationId = cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(metaData, metaDataClazz, "activationIdentifier"));
    return ECIESUtils::buildAssociatedData(applicationKey, out_temporary_key_id, activationId);
}

// ----------------------------------------------------------------------------
// Init & Destroy
// ----------------------------------------------------------------------------

//
// private native void destroy(long handle)
//
CC7_JNI_METHOD_PARAMS(void, destroy, jlong handle)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor || (jlong)encryptor != handle) {
        CC7_ASSERT(false, "Internal object is already destroyed, or provided handle is not ours.");
        return;
    }
    delete encryptor;
}

//
// private native long init(String publicKey, byte[] sharedInfo1, byte[] sharedInfo2)
//
CC7_JNI_METHOD_PARAMS(jlong, init, jstring publicKey, jbyteArray sharedInfo1, jbyteArray sharedInfo2)
{
    auto cppPublicKey = cc7::FromBase64String(cc7::jni::CopyFromJavaString(env, publicKey));
    auto cppSharedInfo1 = cc7::jni::CopyFromJavaByteArray(env, sharedInfo1);
    auto cppSharedInfo2 = cc7::jni::CopyFromJavaByteArray(env, sharedInfo2);
    auto encryptor = new ECIESEncryptor(cppPublicKey, cppSharedInfo1, cppSharedInfo2);
    return reinterpret_cast<jlong>(encryptor);
}

//
// private native long copyHandleForDecryption();
//
CC7_JNI_METHOD(jlong, copyHandleForDecryption)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return 0;
    }
    if (!encryptor->canDecryptResponse()) {
        CC7_ASSERT(false, "Encryptor can't be used for decryption.");
        return 0;
    }
    auto decryptor = new ECIESEncryptor(encryptor->envelopeKey(), encryptor->sharedInfo2());
    return reinterpret_cast<jlong>(decryptor);
}


// ----------------------------------------------------------------------------
// Getters
// ----------------------------------------------------------------------------

//
// public native String getPublicKey();
//
CC7_JNI_METHOD(jstring, getPublicKey)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    auto publicKey = encryptor->publicKey().base64String();
    return cc7::jni::CopyToNullableJavaString(env, publicKey);
}

//
// public native byte[] getSharedInfo1();
//
CC7_JNI_METHOD(jbyteArray, getSharedInfo1)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    return cc7::jni::CopyToNullableJavaByteArray(env, encryptor->sharedInfo1());
}

//
// public native byte[] getSharedInfo2();
//
CC7_JNI_METHOD(jbyteArray, getSharedInfo2)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    return cc7::jni::CopyToNullableJavaByteArray(env, encryptor->sharedInfo2());
}

//
// public native boolean canEncryptRequest();
//
CC7_JNI_METHOD(jboolean, canEncryptRequest)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return (jboolean) false;
    }
    return (jboolean) encryptor->canEncryptRequest();
}

//
// public native boolean canDecryptResponse();
//
CC7_JNI_METHOD(jboolean, canDecryptResponse)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return (jboolean) false;
    }
    return (jboolean) encryptor->canDecryptResponse();
}

// ----------------------------------------------------------------------------
// Encrypt & Decrypt
// ----------------------------------------------------------------------------

//
// public native EciesCryptogram encryptRequestImpl(byte[] requestData, long timestamp);
//
CC7_JNI_METHOD_PARAMS(jobject, encryptRequestImpl, jbyteArray requestData, jlong timestamp)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    // Copy parameters to CPP objects
    auto cppRequestData = cc7::jni::CopyFromJavaByteArray(env, requestData);
    
    // Encrypt request
    ECIESCryptogram cppCryptogram;
    ECIESParameters cppParameters;
    std::string temporaryKeyId;
    cppParameters.timestamp = (cc7::U64)timestamp;
    cppParameters.associatedData = LoadAssociatedData(env, thiz, temporaryKeyId);
    if (cppParameters.associatedData.empty()) {
        return nullptr;
    }
    auto ec = encryptor->encryptRequest(cppRequestData, cppParameters, cppCryptogram);
    if (ec != EC_Ok) {
        CC7_ASSERT(false, "ECIESCryptogram.encryptRequest: failed with error code %d", ec);
        return nullptr;
    }
    return CreateJavaCryptogramFromCppObject(env, cppCryptogram, cppParameters, temporaryKeyId);
}

//
// public native byte[] decryptResponseImpl(ECIESCryptogram cryptogram);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, decryptResponseImpl, jobject cryptogram)
{
    auto encryptor = CC7_THIS_OBJ();
    if (!encryptor) {
        CC7_ASSERT(false, "Missing internal handle.");
        return nullptr;
    }
    // Copy parameters to CPP objects
    ECIESCryptogram cppCryptogram;
    ECIESParameters cppParameters;
    std::string foo;
    cppParameters.associatedData = LoadAssociatedData(env, thiz, foo);
    if (cppParameters.associatedData.empty()) {
        return nullptr;
    }
    LoadCppCryptogramFromJavaObject(env, cryptogram, cppCryptogram, cppParameters);

    // Decrypt response
    cc7::ByteArray cppData;
    auto ec = encryptor->decryptResponse(cppCryptogram, cppParameters, cppData);
    if (ec != EC_Ok) {
        CC7_ASSERT(false, "ECIESCryptogram.decryptResponse: failed with error code %d", ec);
        return nullptr;
    }
    return cc7::jni::CopyToJavaByteArray(env, cppData);
}

CC7_JNI_MODULE_CLASS_END()
