#
# Copyright 2018-2019 Wultra s.r.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

# -------------------------------------------------------------------------
# PowerAuth2 static library
# Contains all multiplatform code
# -------------------------------------------------------------------------
include $(CLEAR_VARS)

NDK_TOOLCHAIN_VERSION := clang

# Library name
LOCAL_MODULE			:= libPowerAuth2
LOCAL_CFLAGS			:= $(EXTERN_CFLAGS)
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++11
LOCAL_CPP_FEATURES		+= exceptions
LOCAL_STATIC_LIBRARIES	:= cc7

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../cc7/include \
	$(LOCAL_PATH)/../cc7/openssl-lib/android/include

# Multiplatform sources
LOCAL_SRC_FILES := \
	PowerAuth/Session.cpp \
	PowerAuth/PublicTypes.cpp \
	PowerAuth/Password.cpp \
	PowerAuth/Debug.cpp \
	PowerAuth/OtpUtil.cpp \
	PowerAuth/ECIES.cpp \
	PowerAuth/crypto/AES.cpp \
	PowerAuth/crypto/Hash.cpp \
	PowerAuth/crypto/KDF.cpp \
	PowerAuth/crypto/MAC.cpp \
	PowerAuth/crypto/ECC.cpp \
	PowerAuth/crypto/PKCS7Padding.cpp \
	PowerAuth/crypto/PRNG.cpp \
	PowerAuth/protocol/Constants.cpp \
	PowerAuth/protocol/PrivateTypes.cpp \
	PowerAuth/protocol/ProtocolUtils.cpp \
	PowerAuth/utils/DataReader.cpp \
	PowerAuth/utils/DataWriter.cpp \
	PowerAuth/utils/URLEncoding.cpp \
	PowerAuth/utils/CRC16.cpp

include $(BUILD_STATIC_LIBRARY)


# -------------------------------------------------------------------------
# PowerAuth2 static unit testing library. 
# Contains all multiplatform unit tests
# -------------------------------------------------------------------------
include $(CLEAR_VARS)

NDK_TOOLCHAIN_VERSION := clang

# Library name
LOCAL_MODULE			:= libPowerAuth2Tests
LOCAL_CFLAGS			:= $(EXTERN_CFLAGS)
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++11
LOCAL_CPP_FEATURES		+= exceptions
LOCAL_STATIC_LIBRARIES	:= cc7tests

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../src/PowerAuth \
	$(LOCAL_PATH)/../cc7/include \
	$(LOCAL_PATH)/../cc7/openssl-lib/android/include

# Multiplatform sources
LOCAL_SRC_FILES := \
	PowerAuthTests/PowerAuthTestsList.cpp \
	PowerAuthTests/pa2CryptoAESTests.cpp \
	PowerAuthTests/pa2CryptoHMACTests.cpp \
	PowerAuthTests/pa2CryptoPKCS7PaddingTests.cpp \
	PowerAuthTests/pa2CryptoECCTests.cpp \
	PowerAuthTests/pa2CryptoECDSATests.cpp \
	PowerAuthTests/pa2CryptoECDHKDFTests.cpp \
	PowerAuthTests/pa2DataWriterReaderTests.cpp \
	PowerAuthTests/pa2MasterSecretKeyComputation.cpp \
	PowerAuthTests/pa2PasswordTests.cpp \
	PowerAuthTests/pa2ProtocolUtilsTests.cpp \
	PowerAuthTests/pa2RecoveryCodeTests.cpp \
	PowerAuthTests/pa2SessionTests.cpp \
	PowerAuthTests/pa2SignatureCalculationTests.cpp \
	PowerAuthTests/pa2SignatureKeysDerivationTest.cpp \
	PowerAuthTests/pa2PublicKeyFingerprintTests.cpp \
	PowerAuthTests/pa2ActivationStatusBlobTests.cpp \
	PowerAuthTests/pa2URLEncodingTests.cpp \
	PowerAuthTests/pa2OtpUtilTests.cpp \
	PowerAuthTests/pa2ECIESTests.cpp \
	PowerAuthTests/pa2CRC16Tests.cpp \
	PowerAuthTests/TestData/pa2.generated/g_pa2Files.cpp

include $(BUILD_STATIC_LIBRARY)

# -------------------------------------------------------------------------
# PowerAuth2 dynamic library 
# Contains final dynamic library (.so) with JNI wrapped methods.
# -------------------------------------------------------------------------
include $(CLEAR_VARS)

NDK_TOOLCHAIN_VERSION := clang

# Library name
LOCAL_MODULE			:= PowerAuth2Module
LOCAL_CFLAGS			:= $(EXTERN_CFLAGS) -fvisibility=hidden -fpic
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -fvisibility=hidden -fpic -std=c++11
LOCAL_CPP_FEATURES		+= exceptions

LOCAL_STATIC_LIBRARIES 	:= PowerAuth2
LOCAL_LDLIBS            := -llog
ifeq ($(NDK_DEBUG),1)
	LOCAL_LDFLAGS       := -Wl,--hash-style=both,--exclude-libs,ALL
else
	LOCAL_LDFLAGS       := -Wl,--hash-style=both,-s,--exclude-libs,ALL
endif

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../cc7/include \
	$(LOCAL_PATH)/../cc7/openssl-lib/android/include

# JNI sources
LOCAL_SRC_FILES := \
	PowerAuth/jni/SessionJNI.cpp \
	PowerAuth/jni/PasswordJNI.cpp \
	PowerAuth/jni/ActivationCodeUtilJNI.cpp \
	PowerAuth/jni/ECIESEncryptorJNI.cpp \
	PowerAuth/jni/TokenCalculatorJNI.cpp \
	PowerAuth/jni/CryptoUtilsJNI.cpp \
	PowerAuth/jni/ProtocolVersionJNI.cpp

include $(BUILD_SHARED_LIBRARY)

# CC7 targets
include $(LOCAL_PATH)/../cc7/src/Android.mk
