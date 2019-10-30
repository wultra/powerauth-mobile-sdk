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

#include <PowerAuth/PublicTypes.h>
#include <PowerAuth/Password.h>
#include <PowerAuth/ECIES.h>

#include <cc7/objc/ObjcHelper.h>

#import "PA2PrivateMacros.h"
#import "PA2Types.h"
#import "PA2ProtocolUpgradeData.h"
#import "PA2Password.h"
#import "PA2ECIESEncryptor.h"
#import "PA2CoreLog.h"

/*
 This header contains various private interfaces, internally used
 in the PA2's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

@interface PA2Password (Private)
- (io::getlime::powerAuth::Password &) passObjRef;
@end

@interface PA2HTTPRequestDataSignature (Private)
- (io::getlime::powerAuth::HTTPRequestDataSignature&) signatureStructRef;
@end

@interface PA2SignedData (Private)
- (io::getlime::powerAuth::SignedData&) signedDataRef;
@end

@interface PA2ECIESCryptogram (Private)
- (io::getlime::powerAuth::ECIESCryptogram &) cryptogramRef;
@end

@interface PA2ECIESEncryptor (Private)
- (id) initWithObject:(const io::getlime::powerAuth::ECIESEncryptor &)objectRef;
- (io::getlime::powerAuth::ECIESEncryptor &) encryptorRef;
@end

@protocol PA2ProtocolUpgradeDataPrivate <PA2ProtocolUpgradeData>
- (void) setupStructure:(io::getlime::powerAuth::ProtocolUpgradeData &)ref;
@end

/**
 Converts PA2SessionSetup object into SessionSetup C++ structure.
 */
CC7_EXTERN_C void PA2SessionSetupToStruct(PA2SessionSetup * setup, io::getlime::powerAuth::SessionSetup & cpp_setup);
/**
 Returns new instance of PA2SessionSetup object, with content copied from SessionSetup C++ structure.
 */
CC7_EXTERN_C PA2SessionSetup * PA2SessionSetupToObject(const io::getlime::powerAuth::SessionSetup & cpp_setup);

/**
 Converts PA2SignatureUnlockKeys object into SignatureUnlockKeys C++ structure.
 */
CC7_EXTERN_C void PA2SignatureUnlockKeysToStruct(PA2SignatureUnlockKeys * keys, io::getlime::powerAuth::SignatureUnlockKeys & cpp_keys);
/**
Converts PA2EncryptedActivationStatus object into EncryptedActivationStatus C++ structure.
 */
CC7_EXTERN_C void PA2EncryptedActivationStatusToStruct(PA2EncryptedActivationStatus * status, io::getlime::powerAuth::EncryptedActivationStatus& cpp_status);
/**
 Returns new instance of PA2ActivationStatus object, with content copied from ActivationStatus C++ structure.
 */
CC7_EXTERN_C PA2ActivationStatus * PA2ActivationStatusToObject(const io::getlime::powerAuth::ActivationStatus& cpp_status);

/**
 Converts PA2HTTPRequestData object into HTTPRequestData C++ structure.
 */
CC7_EXTERN_C void PA2HTTPRequestDataToStruct(PA2HTTPRequestData * req, io::getlime::powerAuth::HTTPRequestData & cpp_req);

/**
 Converts PA2ActivationStep1Param object into ActivationStep1Param C++ structure.
 */
CC7_EXTERN_C void PA2ActivationStep1ParamToStruct(PA2ActivationStep1Param * p1, io::getlime::powerAuth::ActivationStep1Param & cpp_p1);
/**
 Returns new instance of PA2ActivationStep1Result object, with content copied from ActivationStep1Result C++ structure.
 */
CC7_EXTERN_C PA2ActivationStep1Result * PA2ActivationStep1ResultToObject(const io::getlime::powerAuth::ActivationStep1Result& cpp_r1);

/**
 Converts PA2ActivationStep2Param object into ActivationStep2Param C++ structure.
 */
CC7_EXTERN_C void PA2ActivationStep2ParamToStruct(PA2ActivationStep2Param * p2, io::getlime::powerAuth::ActivationStep2Param & cpp_p2);
/**
 Returns new instance of PA2ActivationStep2Result object, with content copied from ActivationStep2Result C++ structure.
 */
CC7_EXTERN_C PA2ActivationStep2Result * PA2ActivationStep2ResultToObject(const io::getlime::powerAuth::ActivationStep2Result& cpp_r2);

/**
 Converts PA2RecoveryData object into RecoveryData C++ structure
 */
CC7_EXTERN_C void PA2RecoveryDataToStruct(PA2RecoveryData * rd, io::getlime::powerAuth::RecoveryData& cpp_rd);
/**
 Returns new instance of PA2RecoveryData object, with content copied from RecoveryData C++ structure
 */
CC7_EXTERN_C PA2RecoveryData * PA2RecoveryDataToObject(const io::getlime::powerAuth::RecoveryData& cpp_rd);

#pragma mark - Debug functions

#if defined(DEBUG)
	CC7_EXTERN_C void PA2Objc_DebugDumpErrorImpl(id instance, NSString * message, io::getlime::powerAuth::ErrorCode code);
	#define PA2Objc_DebugDumpError(instance, message, error_code)	PA2Objc_DebugDumpErrorImpl(instance, message, error_code)
#else
	#define PA2Objc_DebugDumpError(instance, message, error_code)
#endif



