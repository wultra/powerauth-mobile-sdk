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

#include <PowerAuth/Password.h>

#include <cc7/crypto/Crypto.h>
#include <cc7/objc/ObjcHelper.h>

#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreLog.h>
#import <PowerAuthCore/PowerAuthCoreData.h>

/*
 This header contains various private interfaces, internally used
 in the PowerAuthCore's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

//@interface PowerAuthCoreSessionSetup (Private)
//- (powerAuth::SessionSetup&) sessionSetupRef;
//@end

@interface PowerAuthCorePassword (Private)
- (powerAuth::Password &) passObjRef;
@end

//@interface PowerAuthCoreHTTPRequestDataSignature (Private)
//- (powerAuth::HTTPRequestDataSignature&) signatureStructRef;
//@end

//@interface PowerAuthCoreSignedData (Private)
//- (powerAuth::SignedData&) signedDataRef;
//@end

@interface PowerAuthCoreData (Private)
- (id) initWithByteRange:(const cc7::ByteRange &)byteRange;
- (const cc7::ByteRange &) byteArrayRef;
@end


//@protocol PowerAuthCoreProtocolUpgradeDataPrivate <PowerAuthCoreProtocolUpgradeData>
//- (void) setupStructure:(powerAuth::ProtocolUpgradeData &)ref;
//@end

///**
// Converts PowerAuthCoreSignatureUnlockKeys object into SignatureUnlockKeys C++ structure.
// */
//CC7_EXTERN_C void PowerAuthCoreSignatureUnlockKeysToStruct(PowerAuthCoreSignatureUnlockKeys * keys, powerAuth::SignatureUnlockKeys & cpp_keys);
///**
//Converts PowerAuthCoreEncryptedActivationStatus object into EncryptedActivationStatus C++ structure.
// */
//CC7_EXTERN_C void PowerAuthCoreEncryptedActivationStatusToStruct(PowerAuthCoreEncryptedActivationStatus * status, powerAuth::EncryptedActivationStatus& cpp_status);
///**
// Returns new instance of PowerAuthCoreActivationStatus object, with content copied from ActivationStatus C++ structure.
// */
//CC7_EXTERN_C PowerAuthCoreActivationStatus * PowerAuthCoreActivationStatusToObject(const powerAuth::ActivationStatus& cpp_status);
//
///**
// Converts PowerAuthCoreHTTPRequestData object into HTTPRequestData C++ structure.
// */
//CC7_EXTERN_C void PowerAuthCoreHTTPRequestDataToStruct(PowerAuthCoreHTTPRequestData * req, powerAuth::HTTPRequestData & cpp_req);
//
///**
// Converts PowerAuthCoreActivationStep1Param object into ActivationStep1Param C++ structure.
// */
//CC7_EXTERN_C void PowerAuthCoreActivationStep1ParamToStruct(PowerAuthCoreActivationStep1Param * p1, powerAuth::ActivationStep1Param & cpp_p1);
///**
// Returns new instance of PowerAuthCoreActivationStep1Result object, with content copied from ActivationStep1Result C++ structure.
// */
//CC7_EXTERN_C PowerAuthCoreActivationStep1Result * PowerAuthCoreActivationStep1ResultToObject(const powerAuth::ActivationStep1Result& cpp_r1);
//
///**
// Converts PowerAuthCoreActivationStep2Param object into ActivationStep2Param C++ structure.
// */
//CC7_EXTERN_C void PowerAuthCoreActivationStep2ParamToStruct(PowerAuthCoreActivationStep2Param * p2, powerAuth::ActivationStep2Param & cpp_p2);
///**
// Returns new instance of PowerAuthCoreActivationStep2Result object, with content copied from ActivationStep2Result C++ structure.
// */
//CC7_EXTERN_C PowerAuthCoreActivationStep2Result * PowerAuthCoreActivationStep2ResultToObject(const powerAuth::ActivationStep2Result& cpp_r2);

