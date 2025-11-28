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
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++17 -frtti
LOCAL_CPP_FEATURES		+= exceptions
LOCAL_STATIC_LIBRARIES	:= cc7

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../cc7/include \
	$(LOCAL_PATH)/../cc7/openssl-lib/android/include

# Multiplatform sources - PowerAuth/
LOCAL_SRC_FILES += \
	PowerAuth/Session.cpp \
	PowerAuth/Context.cpp \
	PowerAuth/ActivationResult.cpp \
	PowerAuth/ProtocolUpgradeResult.cpp \
	PowerAuth/ActivationStatus.cpp \
	PowerAuth/HttpHeaderHelper.cpp \
	PowerAuth/Algorithms.cpp \
	PowerAuth/PowerAuthSpec.cpp \
	PowerAuth/Exception.cpp \
	PowerAuth/Configuration.cpp \
	PowerAuth/Types.cpp \
	PowerAuth/Request.cpp \
	PowerAuth/Task.cpp \
	PowerAuth/Credentials.cpp \
	PowerAuth/Service.cpp \
	PowerAuth/Encryptor.cpp \
	PowerAuth/AuthenticationService.cpp \
	PowerAuth/TokenService.cpp \
	PowerAuth/TimeService.cpp \
	PowerAuth/SignatureService.cpp \
	PowerAuth/VaultService.cpp \
	PowerAuth/Debug.cpp \
	PowerAuth/Password.cpp \
	PowerAuth/ByteUtils.cpp \
	PowerAuth/KeyProvider.cpp \
	PowerAuth/OtpUtil.cpp \
	PowerAuth/SharedSecret.cpp

# Multiplatform sources - PowerAuth/common
LOCAL_SRC_FILES += \
	PowerAuth/common/CRC16.cpp \
	PowerAuth/common/ThreadSafeNonceGenerator.cpp \
	PowerAuth/common/SecretKeysPool.cpp \
	PowerAuth/common/CommonFunctions.cpp

# Multiplatform sources - PowerAuth/request
LOCAL_SRC_FILES += \
	PowerAuth/request/EndpointSpec.cpp \
	PowerAuth/request/RequestBuilder.cpp

# Multiplatform sources - PowerAuth/task
LOCAL_SRC_FILES += \
	PowerAuth/task/ProtocolUpgradeTask.cpp \
	PowerAuth/task/GetActivationStatusTask.cpp

# Multiplatform sources - PowerAuth/model
LOCAL_SRC_FILES += \
	PowerAuth/model/Constants.cpp \
	PowerAuth/model/SessionData.cpp \
	PowerAuth/model/PersistentData.cpp \
	PowerAuth/model/RegistrationData.cpp \
	PowerAuth/model/UpgradeData.cpp

# Multiplatform sources - PowerAuth/v3
LOCAL_SRC_FILES += \
	PowerAuth/v3/AuthenticationServiceV3.cpp \
	PowerAuth/v3/TokenServiceV3.cpp \
	PowerAuth/v3/ActivationServiceV3.cpp \
	PowerAuth/v3/SecretKeysV3.cpp \
	PowerAuth/v3/KeyProviderV3.cpp \
	PowerAuth/v3/EciesEncryptorFactory.cpp \
	PowerAuth/v3/EciesEncryptor.cpp \
	PowerAuth/v3/EciesUtils.cpp \
	PowerAuth/v3/LegacyKDF.cpp \
	PowerAuth/v3/LegacyUKE.cpp \
	PowerAuth/v3/FunctionsV3.cpp

# Multiplatform sources - PowerAuth/v4
LOCAL_SRC_FILES += \
	PowerAuth/v4/ActivationServiceV4.cpp \
	PowerAuth/v4/AuthenticationServiceV4.cpp \
	PowerAuth/v4/TokenServiceV4.cpp \
	PowerAuth/v4/SecretKeysV4.cpp \
	PowerAuth/v4/KeyProviderV4.cpp \
	PowerAuth/v4/AeadEncryptorFactory.cpp \
	PowerAuth/v4/AeadEncryptor.cpp \
	PowerAuth/v4/AeadUtils.cpp \
	PowerAuth/v4/HybridKeyPair.cpp \
	PowerAuth/v4/PowerAuthAEAD.cpp \
	PowerAuth/v4/PowerAuthKDF.cpp \
	PowerAuth/v4/PowerAuthUKE.cpp \
	PowerAuth/v4/FunctionsV4.cpp

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
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -std=c++17 -frtti
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
	PowerAuthTests/pa2CryptoECCTests.cpp \
	PowerAuthTests/pa2CryptoECDSATests.cpp \
	PowerAuthTests/pa2CryptoECDHKDFTests.cpp \
	PowerAuthTests/pa2DataWriterReaderTests.cpp \
	PowerAuthTests/pa2ByteUtilsTests.cpp \
	PowerAuthTests/pa2MasterSecretKeyComputation.cpp \
	PowerAuthTests/pa2PasswordTests.cpp \
	PowerAuthTests/pa2ProtocolUtilsTests.cpp \
	PowerAuthTests/pa2SessionTests.cpp \
	PowerAuthTests/pa2SessionSetupTests.cpp \
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
LOCAL_CPPFLAGS			:= $(EXTERN_CFLAGS) -fvisibility=hidden -fpic -std=c++17 -frtti
LOCAL_CPP_FEATURES		+= exceptions

LOCAL_STATIC_LIBRARIES 	:= PowerAuth2
LOCAL_LDLIBS            := -llog
ifeq ($(NDK_DEBUG),1)
	LOCAL_LDFLAGS       := -Wl,-z,max-page-size=16384,--hash-style=both,--exclude-libs,ALL
else
	LOCAL_LDFLAGS       := -Wl,-z,max-page-size=16384,--hash-style=both,-s,--exclude-libs,ALL
endif

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../cc7/include \
	$(LOCAL_PATH)/../cc7/openssl-lib/android/include

# JNI sources
LOCAL_SRC_FILES := \
	PowerAuthJni/SessionJNI.cpp \
	PowerAuthJni/PasswordJNI.cpp \
	PowerAuthJni/ActivationCodeUtilJNI.cpp \
	PowerAuthJni/TokenCalculatorJNI.cpp \
	PowerAuthJni/CryptoUtilsJNI.cpp \
	PowerAuthJni/ProtocolVersionJNI.cpp \
	PowerAuthJni/EcPrivateKeyJNI.cpp \
	PowerAuthJni/EcPublicKeyJNI.cpp \
	PowerAuthJni/SecureDataJNI.cpp

include $(BUILD_SHARED_LIBRARY)

# CC7 targets
include $(LOCAL_PATH)/../cc7/src/Android.mk
