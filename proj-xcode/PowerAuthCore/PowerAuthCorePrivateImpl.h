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

#include <PowerAuth/PublicTypes.h>
#include <PowerAuth/Password.h>
#include <PowerAuth/ECIES.h>

#include <cc7/objc/ObjcHelper.h>

#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreLog.h>

/*
 This header contains various private interfaces, internally used
 in the PowerAuthCore's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

@interface PowerAuthCorePassword (Private)
- (io::getlime::powerAuth::Password &) passObjRef;
@end

@interface PowerAuthCoreHTTPRequestDataSignature (Private)
- (io::getlime::powerAuth::HTTPRequestDataSignature&) signatureStructRef;
@end

@interface PowerAuthCoreSignedData (Private)
- (io::getlime::powerAuth::SignedData&) signedDataRef;
@end

@interface PowerAuthCoreEciesCryptogram (Private)
- (io::getlime::powerAuth::ECIESCryptogram &) cryptogramRef;
@end

@interface PowerAuthCoreEciesEncryptor (Private)
- (id) initWithObject:(const io::getlime::powerAuth::ECIESEncryptor &)objectRef;
- (io::getlime::powerAuth::ECIESEncryptor &) encryptorRef;
@end

@protocol PowerAuthCoreProtocolUpgradeDataPrivate <PowerAuthCoreProtocolUpgradeData>
- (void) setupStructure:(io::getlime::powerAuth::ProtocolUpgradeData &)ref;
@end

/**
 Converts PowerAuthCoreSessionSetup object into SessionSetup C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreSessionSetupToStruct(PowerAuthCoreSessionSetup * setup, io::getlime::powerAuth::SessionSetup & cpp_setup);
/**
 Returns new instance of PowerAuthCoreSessionSetup object, with content copied from SessionSetup C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreSessionSetup * PowerAuthCoreSessionSetupToObject(const io::getlime::powerAuth::SessionSetup & cpp_setup);

/**
 Converts PowerAuthCoreSignatureUnlockKeys object into SignatureUnlockKeys C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreSignatureUnlockKeysToStruct(PowerAuthCoreSignatureUnlockKeys * keys, io::getlime::powerAuth::SignatureUnlockKeys & cpp_keys);
/**
Converts PowerAuthCoreEncryptedActivationStatus object into EncryptedActivationStatus C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreEncryptedActivationStatusToStruct(PowerAuthCoreEncryptedActivationStatus * status, io::getlime::powerAuth::EncryptedActivationStatus& cpp_status);
/**
 Returns new instance of PowerAuthCoreActivationStatus object, with content copied from ActivationStatus C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreActivationStatus * PowerAuthCoreActivationStatusToObject(const io::getlime::powerAuth::ActivationStatus& cpp_status);

/**
 Converts PowerAuthCoreHTTPRequestData object into HTTPRequestData C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreHTTPRequestDataToStruct(PowerAuthCoreHTTPRequestData * req, io::getlime::powerAuth::HTTPRequestData & cpp_req);

/**
 Converts PowerAuthCoreActivationStep1Param object into ActivationStep1Param C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreActivationStep1ParamToStruct(PowerAuthCoreActivationStep1Param * p1, io::getlime::powerAuth::ActivationStep1Param & cpp_p1);
/**
 Returns new instance of PowerAuthCoreActivationStep1Result object, with content copied from ActivationStep1Result C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreActivationStep1Result * PowerAuthCoreActivationStep1ResultToObject(const io::getlime::powerAuth::ActivationStep1Result& cpp_r1);

/**
 Converts PowerAuthCoreActivationStep2Param object into ActivationStep2Param C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreActivationStep2ParamToStruct(PowerAuthCoreActivationStep2Param * p2, io::getlime::powerAuth::ActivationStep2Param & cpp_p2);
/**
 Returns new instance of PowerAuthCoreActivationStep2Result object, with content copied from ActivationStep2Result C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreActivationStep2Result * PowerAuthCoreActivationStep2ResultToObject(const io::getlime::powerAuth::ActivationStep2Result& cpp_r2);

/**
 Converts PowerAuthCoreRecoveryData object into RecoveryData C++ structure
 */
CC7_EXTERN_C void PowerAuthCoreRecoveryDataToStruct(PowerAuthCoreRecoveryData * rd, io::getlime::powerAuth::RecoveryData& cpp_rd);
/**
 Returns new instance of PowerAuthCoreRecoveryData object, with content copied from RecoveryData C++ structure
 */
CC7_EXTERN_C PowerAuthCoreRecoveryData * PowerAuthCoreRecoveryDataToObject(const io::getlime::powerAuth::RecoveryData& cpp_rd);

#pragma mark - Debug functions

#if defined(DEBUG)
    CC7_EXTERN_C void PowerAuthCoreObjc_DebugDumpErrorImpl(id instance, NSString * message, io::getlime::powerAuth::ErrorCode code);
    #define PowerAuthCoreObjc_DebugDumpError(instance, message, error_code) PowerAuthCoreObjc_DebugDumpErrorImpl(instance, message, error_code)
#else
    #define PowerAuthCoreObjc_DebugDumpError(instance, message, error_code)
#endif



