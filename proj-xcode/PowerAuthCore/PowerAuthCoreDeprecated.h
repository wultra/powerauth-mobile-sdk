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

#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>

// Password

/**
 The `PA2Password` is now deprecated, please use `PowerAuthCorePassword` instead.
 */
typedef PowerAuthCorePassword PA2Password POWERAUTH_DEPRECATED(1.6.0);
/**
 The `PA2MutablePassword` is now deprecated, please use `PowerAuthCoreMutablePassword` instead.
 */
typedef PowerAuthCoreMutablePassword PA2MutablePassword POWERAUTH_DEPRECATED(1.6.0);

// ECIES

/**
 The `PA2ECIESEncryptor` is now deprecated, please use `PowerAuthCoreEciesEncryptor` instead.
 */
typedef PowerAuthCoreEciesEncryptor PA2ECIESEncryptor POWERAUTH_DEPRECATED(1.6.0);
/**
 The `PA2ECIESCryptogram` is now deprecated, please use `PowerAuthCoreEciesCryptogram` instead.
 */
typedef PowerAuthCoreEciesCryptogram PA2ECIESCryptogram POWERAUTH_DEPRECATED(1.6.0);
/**
 The `PA2ECIESMetaData` is now deprecated, please use `PowerAuthCoreEciesMetaData` instead.
 */
typedef PowerAuthCoreEciesMetaData PA2ECIESMetaData POWERAUTH_DEPRECATED(1.6.0);
/**
 The `PA2ECIESEncryptorScope` is now deprecated, please use `PowerAuthCoreEciesEncryptorScope` instead.
 */
typedef PowerAuthCoreEciesEncryptorScope PA2ECIESEncryptorScope POWERAUTH_DEPRECATED(1.6.0);

// Crypto utils

/**
 The `PA2CryptoUtils` is now deprecated, please use `PowerAuthCoreCryptoUtils` instead.
 */
typedef PowerAuthCoreCryptoUtils PA2CryptoUtils POWERAUTH_DEPRECATED(1.6.0);
/**
 The `PA2ECPublicKey` is now deprecated, please use `PowerAuthCoreECPublicKey` instead.
 */
typedef PowerAuthCoreECPublicKey PA2ECPublicKey POWERAUTH_DEPRECATED(1.6.0);
