/*
 * Copyright 2016-2017 Wultra s.r.o.
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

#include "EncryptorJNI.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH	    	"io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE	    io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS  		Encryptor
#define CC7_JNI_CPP_CLASS		    Encryptor
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

jobject CreateJavaEncryptorForCppClass(JNIEnv * env, Encryptor * encryptor, int errorCode)
{
	if (!env) {
		CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
		return NULL;
	}
	// Create Encryptor java class instance
	jclass  resultClazz  = CC7_JNI_MODULE_FIND_CLASS("Encryptor");
	jobject resultObject = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("Encryptor"), "()V");
	if (!resultObject) {
		return NULL;
	}
	// ...and set object pointer to "handle" field 
	CC7_JNI_SET_FIELD_LONG(resultObject, resultClazz, "handle", 		reinterpret_cast<jlong>(encryptor));
	CC7_JNI_SET_FIELD_INT (resultObject, resultClazz, "lastErrorCode",	errorCode);
	return resultObject;
}

static void SetLastErrorCode(JNIEnv* env, jobject object, ErrorCode code)
{
	static jfieldID s_FieldID = 0;
	if (s_FieldID == 0) {
		jclass clazz = CC7_JNI_MODULE_FIND_CLASS("Encryptor");
		s_FieldID    = CC7_JNI_FIELD_INT(clazz, "lastErrorCode");	
	}
	if (object) {
		env->SetIntField(object, s_FieldID, (jint)code);
	}
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

// ----------------------------------------------------------------------------
// Getters
// ----------------------------------------------------------------------------

//
// public native int encryptorMode();
//
CC7_JNI_METHOD(jint, encryptorMode)
{
	auto encryptor = CC7_THIS_OBJ();
	if (!encryptor) {
		return 0;
	}
	return (jint)encryptor->encryptionMode();
}

//
// public native byte[] sessionIndex();
//
CC7_JNI_METHOD(jbyteArray, sessionIndex)
{
	auto encryptor = CC7_THIS_OBJ();
	if (!encryptor) {
		return NULL;
	}
	return cc7::jni::CopyToJavaByteArray(env, encryptor->sessionIndex());
}

// ----------------------------------------------------------------------------
// Encrypt / Decrypt
// ----------------------------------------------------------------------------

// 
// public native EncryptedMessage encrypt(byte[] data);
//
CC7_JNI_METHOD_PARAMS(jobject, encrypt, jbyteArray data)
{
	ErrorCode code = EC_WrongParam;
	jobject robj = NULL;
	auto encryptor = CC7_THIS_OBJ();
	if (NULL != encryptor) {
	 	auto cpp_data = cc7::jni::CopyFromJavaByteArray(env, data);
		EncryptedMessage cpp_msg;
		code = encryptor->encrypt(cpp_data, cpp_msg);
		if (EC_Ok == code) {
			jclass rclazz = CC7_JNI_MODULE_FIND_CLASS("EncryptedMessage");
			robj = cc7::jni::CreateJavaObject(env, CC7_JNI_MODULE_CLASS_PATH("EncryptedMessage"), "()V");
			// Copy properties from CPP structure to EncryptedMessage java object
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "applicationKey",  		cc7::jni::CopyToNullableJavaString(env, cpp_msg.applicationKey));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "activationId",  		cc7::jni::CopyToNullableJavaString(env, cpp_msg.activationId));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "encryptedData",  		cc7::jni::CopyToJavaString(env, cpp_msg.encryptedData));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "mac",  					cc7::jni::CopyToJavaString(env, cpp_msg.mac));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "sessionIndex",  		cc7::jni::CopyToJavaString(env, cpp_msg.sessionIndex));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "adHocIndex", 	 		cc7::jni::CopyToJavaString(env, cpp_msg.adHocIndex));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "macIndex", 	 			cc7::jni::CopyToJavaString(env, cpp_msg.macIndex));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "nonce", 	 			cc7::jni::CopyToJavaString(env, cpp_msg.nonce));
			CC7_JNI_SET_FIELD_STRING(robj, rclazz, "ephemeralPublicKey",	cc7::jni::CopyToNullableJavaString(env, cpp_msg.ephemeralPublicKey));
			//
		}
	}
	// Update error code & return created java object 
	SetLastErrorCode(env, thiz, code);
	return robj;
}

//
// public native byte[] decrypt(EncryptedMessage message);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, decrypt, jobject message)
{
	ErrorCode code = EC_WrongParam;
	jbyteArray result = NULL;
	auto encryptor = CC7_THIS_OBJ();
	if (NULL != encryptor && NULL != message) {
		EncryptedMessage cpp_msg;
		jclass messageClazz  = CC7_JNI_MODULE_FIND_CLASS("EncryptedMessage");
		// Copy properties from EncryptedMessage java object into CPP structure
		cpp_msg.applicationKey		= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "applicationKey"));
		cpp_msg.activationId		= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "activationId"));
		cpp_msg.encryptedData		= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "encryptedData"));
		cpp_msg.mac					= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "mac"));
		cpp_msg.sessionIndex		= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "sessionIndex"));
		cpp_msg.adHocIndex			= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "adHocIndex"));
		cpp_msg.macIndex			= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "macIndex"));
		cpp_msg.nonce				= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "nonce"));
		cpp_msg.ephemeralPublicKey	= cc7::jni::CopyFromJavaString(env, CC7_JNI_GET_FIELD_STRING(message, messageClazz, "ephemeralPublicKey"));
		//
		cc7::ByteArray cpp_data;
		code = encryptor->decrypt(cpp_msg, cpp_data);
		if (EC_Ok == code) {
			result = cc7::jni::CopyToJavaByteArray(env, cpp_data);
		}
	}
	// Update error code & return created byte array
	SetLastErrorCode(env, thiz, code);
	return result;
}

CC7_JNI_MODULE_CLASS_END()
