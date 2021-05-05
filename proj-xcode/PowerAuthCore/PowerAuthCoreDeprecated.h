/*
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

#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>

// Session

/**
 The `PA2Session` is now deprecated, please use `PowerAuthCoreSession` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2Session, PowerAuthCoreSession)

// Password

/**
 The `PA2Password` is now deprecated, please use `PowerAuthCorePassword` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2Password, PowerAuthCorePassword)
/**
 The `PA2MutablePassword` is now deprecated, please use `PowerAuthCoreMutablePassword` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2MutablePassword, PowerAuthCoreMutablePassword)

// ECIES

/**
 The `PA2ECIESEncryptor` is now deprecated, please use `PowerAuthCoreEciesEncryptor` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2ECIESEncryptor, PowerAuthCoreEciesEncryptor)
/**
 The `PA2ECIESCryptogram` is now deprecated, please use `PowerAuthCoreEciesCryptogram` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2ECIESCryptogram, PowerAuthCoreEciesCryptogram)
/**
 The `PA2ECIESMetaData` is now deprecated, please use `PowerAuthCoreEciesMetaData` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2ECIESMetaData, PowerAuthCoreEciesMetaData)
/**
 The `PA2ECIESEncryptorScope` is now deprecated, please use `PowerAuthCoreEciesEncryptorScope` instead.
 */
POWERAUTH_DEPRECATED_TYPE(1.6.0, PA2ECIESEncryptorScope, PowerAuthCoreEciesEncryptorScope)

// Crypto utils

/**
 The `PA2CryptoUtils` is now deprecated, please use `PowerAuthCoreCryptoUtils` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2CryptoUtils, PowerAuthCoreCryptoUtils)
/**
 The `PA2ECPublicKey` is now deprecated, please use `PowerAuthCoreECPublicKey` instead.
 */
POWERAUTH_DEPRECATED_CLASS(1.6.0, PA2ECPublicKey, PowerAuthCoreECPublicKey)
