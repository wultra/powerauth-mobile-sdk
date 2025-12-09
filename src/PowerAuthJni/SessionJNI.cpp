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

#include "SecureDataJNI.h"
#include <PowerAuth/Session.h>
#include <PowerAuth/Debug.h>
#include <map>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          Session
#define CC7_JNI_CPP_CLASS           Session
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;

CC7_JNI_MODULE_CLASS_BEGIN()

// ----------------------------------------------------------------------------
// Init & Destroy
// ----------------------------------------------------------------------------

//
// private native long init(SessionSetup setup)
//
CC7_JNI_METHOD_PARAMS(jlong, init, jobject setup)
{
    return 0;
}

//
// private native void destroy(long handle)
//
CC7_JNI_METHOD_PARAMS(void, destroy, jlong handle)
{
}

//
// public native void resetSession(boolean fullReset)
//
CC7_JNI_METHOD_PARAMS(void, resetSession, jboolean fullReset)
{
}

//
// public native boolean hasDebugFeatures()
//
CC7_JNI_METHOD(jboolean, hasDebugFeatures)
{
    return false;
}

//
// public native boolean hasValidSetup();
//
CC7_JNI_METHOD(jboolean, hasValidSetup)
{
    return false;
}

//
// public native String getApplicationKey();
//
CC7_JNI_METHOD(jstring, getApplicationKey)
{
    return nullptr;
}

//
// public native ProtocolVersion getProtocolVersion()
//
CC7_JNI_METHOD(jobject, getProtocolVersion)
{
    return nullptr;
}

// ----------------------------------------------------------------------------
// Serialization
// ----------------------------------------------------------------------------

//
// public native byte[] serializedState();
//
CC7_JNI_METHOD(jbyteArray, serializedState)
{
    return nullptr;
}

//
// public native int deserializeState(byte[] state);
//
CC7_JNI_METHOD_PARAMS(jint, deserializeState, jbyteArray state)
{
    return 0;
}


// ----------------------------------------------------------------------------
// Activation
// ----------------------------------------------------------------------------

//
// public native boolean canStartActivation();
//
CC7_JNI_METHOD(jboolean, canStartActivation)
{
    return false;
}

//
// public native boolean hasPendingActivation();
//
CC7_JNI_METHOD(jboolean, hasPendingActivation)
{
    return false;
}

//
// public native boolean hasValidActivation();
//
CC7_JNI_METHOD(jboolean, hasValidActivation)
{
    return false;
}

//
// public native String getActivationIdentifier()
//
CC7_JNI_METHOD(jstring, getActivationIdentifier)
{
    return nullptr;
}

//
// public native String getActivationFingerprint()
//
CC7_JNI_METHOD(jstring, getActivationFingerprint)
{
    return nullptr;
}

//
// public native ActivationStep1Result startActivation(ActivationStep1Param param);
//
CC7_JNI_METHOD_PARAMS(jobject, startActivation, jobject param)
{
    return nullptr;
}

//
// public native ActivationStep2Result validateActivationResponse(ActivationStep2Param param);
//
CC7_JNI_METHOD_PARAMS(jobject, validateActivationResponse, jobject param)
{
    return nullptr;
}

//
// public native int completeActivation(SignatureUnlockKeys lockKeys);
//
CC7_JNI_METHOD_PARAMS(jint, completeActivation, jobject lockKeys)
{
    return 0;
}


// ----------------------------------------------------------------------------
// Activation status
// ----------------------------------------------------------------------------

//
// public native ActivationStatus decodeActivationStatus(EncryptedActivationStatus encryptedStatus, SignatureUnlockKeys unlockKeys, Map<String, Object> customObject);
//
CC7_JNI_METHOD_PARAMS(jobject, decodeActivationStatus, jobject encryptedStatus, jobject unlockKeys, jobject customObject)
{
    return nullptr;
}


// ----------------------------------------------------------------------------
// Data signing
// ----------------------------------------------------------------------------

//
// private native byte[] prepareKeyValueDictionaryForDataSigning(String[] keys, String[] values);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, prepareKeyValueDictionaryForDataSigning, jobjectArray keys, jobjectArray values)
{
    return nullptr;
}

//
// public native SignatureResult signHTTPRequest(SignatureRequest request, SignatureUnlockKeys unlockKeys, int signatureFactor);
//
CC7_JNI_METHOD_PARAMS(jobject, signHTTPRequest, jobject request, jobject unlockKeys, jint signatureFactor)
{
    return nullptr;
}

//
// public native String getHttpAuthHeaderName();
//
CC7_JNI_METHOD(jstring, getHttpAuthHeaderName)
{
    return nullptr;
}

//
// public native int verifyServerSignedData(SignedData signedData);
//
CC7_JNI_METHOD_PARAMS(jint, verifyServerSignedData, jobject signedData)
{
    return 0;
}

//
// public native int signDataWithHmacKey(SignedData dataToSign, SignatureUnlockKeys unlockKeys)
//
CC7_JNI_METHOD_PARAMS(jint, signDataWithHmacKey, jobject dataToSign, jobject unlockKeys)
{
    return 0;
}

// ----------------------------------------------------------------------------
// Signature keys management
// ----------------------------------------------------------------------------

//
// public native int changeUserPassword(Password oldPassword, Password newPassword);
//
CC7_JNI_METHOD_PARAMS(jint, changeUserPassword, jobject oldPassword, jobject newPassword)
{
    return 0;
}

//
// public native int addBiometryFactor(String cVaultKey, SignatureUnlockKeys unlockKeys);
//
CC7_JNI_METHOD_PARAMS(jint, addBiometryFactor, jstring cVaultKey, jobject unlockKeys)
{
    return 0;
}

//
// public native boolean hasBiometryFactor();
//
CC7_JNI_METHOD(jboolean, hasBiometryFactor)
{
    return false;
}

//
// public native int removeBiometryFactor();
//
CC7_JNI_METHOD(jint, removeBiometryFactor)
{
    return 0;
}


// ----------------------------------------------------------------------------
// Vault operations
// ----------------------------------------------------------------------------

//
// public native SecureData deriveCryptographicKeyFromVaultKey(String cVaultKey, SignatureUnlockKeys unlockKeys, long keyIndex);
//
CC7_JNI_METHOD_PARAMS(jobject, deriveCryptographicKeyFromVaultKey, jstring cVaultKey, jobject unlockKeys, jlong keyIndex)
{
    return nullptr;
}

//
// public native byte[] signDataWithDevicePrivateKey(String cVaultKey, SignatureUnlockKeys unlockKeys, byte[] data, int signatureFormat);
//
CC7_JNI_METHOD_PARAMS(jbyteArray, signDataWithDevicePrivateKey, jstring cVaultKey, jobject unlockKeys, jbyteArray data, jint signatureFormat)
{
    return nullptr;
}


// ----------------------------------------------------------------------------
// External Encryption Key
// ----------------------------------------------------------------------------

//
// public native bool hasExternalEncryptionKey();
//
CC7_JNI_METHOD(jboolean, hasExternalEncryptionKey)
{
    return false;
}

//
// public native int setExternalEncryptionKey(SecureData externalEncryptionKey);
//
CC7_JNI_METHOD_PARAMS(jint, setExternalEncryptionKey, jobject eek)
{
    return 0;
}

//
// public native int addExternalEncryptionKey(SecureData externalEncryptionKey);
//
CC7_JNI_METHOD_PARAMS(jint, addExternalEncryptionKey, jobject eek)
{
    return 0;
}

// 
// public native int removeExternalEncryptionKey();
//
CC7_JNI_METHOD(jint, removeExternalEncryptionKey)
{
    return 0;
}

// ----------------------------------------------------------------------------
// ECIES
// ----------------------------------------------------------------------------

//
// private native EciesEncryptor getEciesEncryptorImpl(int scope, SignatureUnlockKeys unlockKeys, byte[] sharedInfo1, ICoreTimeService timeService);
//
CC7_JNI_METHOD_PARAMS(jobject, getEciesEncryptorImpl, jint scope, jobject unlockKeys, jbyteArray sharedInfo1, jobject timeService)
{
    return nullptr;
}

//
// public native int setPublicKeyForEciesScope(int scope, String publicKey, String publicKeyId)
//
CC7_JNI_METHOD_PARAMS(jint, setPublicKeyForEciesScope, jint scope, jstring publicKey, jstring publicKeyId)
{
    return 0;
}

//
// public native int removePublicKeyForEciesScope(int scope)
//
CC7_JNI_METHOD_PARAMS(void, removePublicKeyForEciesScope, jint scope)
{
}

//
// public native boolean hasPublicKeyForEciesScope(int scope)
//
CC7_JNI_METHOD_PARAMS(jboolean, hasPublicKeyForEciesScope, jint scope)
{
    return false;
}

//
// public native String getPublicKeyIdForEciesScope(int scope)
//
CC7_JNI_METHOD_PARAMS(jstring, getPublicKeyIdForEciesScope, jint scope)
{
    return nullptr;
}

// ----------------------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------------------

//
// public native SecureData normalizeSignatureUnlockKeyFromData(byte[] arbitraryData);
//
CC7_JNI_METHOD_PARAMS(jobject, normalizeSignatureUnlockKeyFromData, jbyteArray arbitraryData)
{
    return nullptr;
}

//
// public native SecureData generateSignatureUnlockKey();
//
CC7_JNI_METHOD(jobject, generateSignatureUnlockKey)
{
    return nullptr;
}

//
// public native String generateActivationStatusChallenge()
//
CC7_JNI_METHOD(jstring, generateActivationStatusChallenge)
{
    return nullptr;
}

// ----------------------------------------------------------------------------
// Protocol upgrade
// ----------------------------------------------------------------------------

//
// public native boolean hasProtocolUpgradeAvailable();
//
CC7_JNI_METHOD(jboolean, hasProtocolUpgradeAvailable)
{
    return false;
}

//
// public native boolean hasPendingProtocolUpgrade();
//
CC7_JNI_METHOD(jboolean, hasPendingProtocolUpgrade)
{
    return false;
}

//
// public native ProtocolVersion getPendingProtocolUpgradeVersion();
//
CC7_JNI_METHOD(jobject, getPendingProtocolUpgradeVersion)
{
    return nullptr;
}

//
// public native int startProtocolUpgrade();
//
CC7_JNI_METHOD(jint, startProtocolUpgrade)
{
    return 0;
}

//
// public native int applyProtocolUpgradeData(ProtocolUpgradeData protocolUpgradeData);
//
CC7_JNI_METHOD_PARAMS(jint, applyProtocolUpgradeData, jobject md)
{
    return 0;
}

//
// public native int finishProtocolUpgrade();
//
CC7_JNI_METHOD(jint, finishProtocolUpgrade)
{
    return 0;
}

//
// private static native String getMaxSupportedHttpProtocolVersion(int protocolVersionValue)
//
CC7_JNI_METHOD_PARAMS(jstring, getMaxSupportedHttpProtocolVersion, jint protocolVersionValue)
{
    return nullptr;
}

CC7_JNI_MODULE_CLASS_END()
