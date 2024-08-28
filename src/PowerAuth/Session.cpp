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

#include <PowerAuth/Session.h>
#include <PowerAuth/ECIES.h>
#include <PowerAuth/OtpUtil.h>

#include <cc7/Base64.h>
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"
#include "crypto/CryptoUtils.h"
#include "utils/URLEncoding.h"
#include "utils/DataReader.h"
#include "utils/DataWriter.h"
#include <algorithm>

using namespace cc7;

namespace io
{
namespace getlime
{
namespace powerAuth
{
    
#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(_lock)
    
    // MARK: Construction / Destruction -
    
    Session::Session(const SessionSetup & setup) :
        _state(SS_Empty),
        _setup(setup),
        _pd(nullptr),
        _ad(nullptr)
    {
        if (protocol::ValidateSessionSetup(_setup, false)) {
            CC7_LOG("Session %p: Object created.", this);
        } else {
            _state = SS_Invalid;
            CC7_LOG("Session %p: Object created, but SessionSetup is invalid!", this);
        }
    }
    
    Session::~Session()
    {
        delete _pd;
        delete _ad;
        
        CC7_LOG("Session %p: Object destroyed.", this);
    }
    
    void Session::resetSession()
    {
        LOCK_GUARD();
        commitNewPersistentState(nullptr, SS_Empty);
    }
    
    const SessionSetup * Session::sessionSetup() const
    {
        LOCK_GUARD();
        return hasValidSetup() ? &_setup : nullptr;
    }
    
    std::string Session::applicationKey() const
    {
        LOCK_GUARD();
        return hasValidSetup() ? _setup.applicationKey : std::string();
    }
    
    // MARK: - State probing -
    
    bool Session::hasValidSetup() const
    {
        LOCK_GUARD();
        return _state >= SS_Empty;
    }
    
    bool Session::canStartActivation() const
    {
        LOCK_GUARD();
        if (_state == SS_Empty) {
            if (CC7_CHECK(_pd == nullptr && _ad == nullptr, "Internal error. PD should be null when state is SS_Empty")) {
                return true;
            }
        }
        return false;
    }
    
    bool Session::hasPendingActivation() const
    {
        LOCK_GUARD();
        if (_state == SS_Activation1 || _state == SS_Activation2) {
            if (CC7_CHECK(_pd == nullptr && _ad != nullptr, "Internal error. Only AD should be valid during the pending activation.")) {
                return true;
            }
        }
        return false;
    }
    
    bool Session::hasValidActivation() const
    {
        LOCK_GUARD();
        if (_state == SS_Activated) {
            if (CC7_CHECK(_pd != nullptr && _ad == nullptr, "Internal error. Only PD & setup should be valid when activated.")) {
                return true;
            }
        }
        return false;
    }
    
    bool Session::hasProtocolUpgradeAvailable() const
    {
        LOCK_GUARD();
        if (hasValidActivation()) {
            return _pd->protocolVersion() != Version_Latest &&
                    _pd->flags.pendingUpgradeVersion == Version_NA;
        }
        return false;
    }

    bool Session::hasPendingProtocolUpgrade() const
    {
        LOCK_GUARD();
        if (hasValidActivation()) {
            return _pd->flags.pendingUpgradeVersion != Version_NA;
        }
        return false;
    }
    
    Version Session::protocolVersion() const
    {
        LOCK_GUARD();
        if (hasValidActivation()) {
            return _pd->protocolVersion();
        }
        return Version_Latest;
    }
    
    // MARK: - Serialization -
    
    const cc7::byte HAS_PERSISTENT_DATA = 1 << 1;
    const cc7::byte DATA_TAG = 'P';
    const cc7::byte DATA_VER = 'A';
    
    
    cc7::ByteArray Session::saveSessionState() const
    {
        LOCK_GUARD();
        cc7:byte flags = 0;
        if (hasValidActivation()) {
            flags |= HAS_PERSISTENT_DATA;
        }
        utils::DataWriter writer;
        
        writer.openVersion(DATA_TAG, DATA_VER);
        writer.writeByte(flags);
        
        if (flags & HAS_PERSISTENT_DATA) {
            protocol::SerializePersistentData(*_pd, writer);
        }
        writer.closeVersion();
        
        return writer.serializedData();
    }
    
    ErrorCode Session::loadSessionState(const cc7::ByteRange & serialized_state)
    {
        LOCK_GUARD();
        utils::DataReader reader(serialized_state);
        cc7::byte flags = 0;
        
        bool has_data  = false;
        auto new_data = new protocol::PersistentData();
        
        bool result = reader.openVersion(DATA_TAG, DATA_VER) &&
                      reader.readByte(flags);
        
        if (result && (flags != 'M')) {
            if (flags & HAS_PERSISTENT_DATA) {
                result = result && protocol::DeserializePersistentData(*new_data, reader);
                has_data = result;
            }
        } else {
            result = has_data = false;
        }
        
        State new_state = has_data ? SS_Activated : SS_Empty;
        commitNewPersistentState(new_data, new_state);
        return result ? EC_Ok : EC_WrongParam;
    }
    
    
    
    // MARK: - Activation -
    
    std::string Session::activationIdentifier() const
    {
        LOCK_GUARD();
        if (hasValidActivation()) {
            return _pd->activationId;
        } else if (hasPendingActivation()) {
            return _ad->activationId;
        }
        return std::string();
    }
    
    std::string Session::activationFingerprint() const
    {
        LOCK_GUARD();
        std::string result;
        if (hasValidActivation() || (hasPendingActivation() && _state == SS_Activation2)) {
            if (_state == SS_Activation2) {
                // Still pending activation
                result = protocol::CalculateActivationFingerprint(_ad->devicePublicKeyData, _ad->serverPublicKeyData, _ad->activationId, Version_Latest);
            } else {
                // Has valid activation
                result = protocol::CalculateActivationFingerprint(_pd->devicePublicKey, _pd->serverPublicKey, _pd->activationId, _pd->protocolVersion());
            }
            if (result.empty()) {
                CC7_LOG("Session %p: ActivationFingerprint: Unable to calculate activation fingerprint.", this);
            }
        }
        return result;
    }
    
    ErrorCode Session::startActivation(const ActivationStep1Param & param, ActivationStep1Result & result)
    {
        LOCK_GUARD();
        // Validate state & parameters
        if (!hasValidSetup()) {
            CC7_LOG("Session %p: Step 1: Session has no valid setup.", this);
            return EC_WrongState;
        }
        if (!canStartActivation()) {
            CC7_LOG("Session %p: Step 1: Called in wrong state.", this);
            return EC_WrongState;
        }
        if (!param.activationCode.empty()) {
            // If activation code is present, then check whether CRC16 checksum is OK
            if (!OtpUtil::validateActivationCode(param.activationCode)) {
                CC7_LOG("Session %p: Step 1: Wrong activation code.", this);
                return EC_WrongParam;
            }
        }
        
        auto error_code = EC_Encryption;
        auto ad = new protocol::ActivationData();
        
        do {
            crypto::BNContext ctx;
            
            // Import master server public key & try to validate OTP+ShortID signature
            ad->masterServerPublicKey = crypto::ECC_ImportPublicKeyFromB64(nullptr, _setup.masterServerPublicKey, ctx);
            if (nullptr == ad->masterServerPublicKey) {
                CC7_LOG("Session %p: Step 1: Master server public key is invalid.", this);
                break;
            }
            if (!protocol::ValidateActivationCodeSignature(param.activationCode, param.activationSignature, ad->masterServerPublicKey)) {
                CC7_LOG("Session %p: Step 1: Invalid OTP+ShortID signature.", this);
                break;
            }
            
            // Re-seed OpenSSL's PRNG.
            crypto::ReseedPRNG();
            
            // Generate device's private & public key pair
            ad->devicePrivateKey = crypto::ECC_GenerateKeyPair();
            if (nullptr == ad->devicePrivateKey) {
                CC7_LOG("Session %p: Step 1: Private key pair generator failed.", this);
                break;
            }
            ad->devicePublicKeyData = crypto::ECC_ExportPublicKey(ad->devicePrivateKey, ctx);
            if (ad->devicePublicKeyData.empty()) {
                CC7_LOG("Session %p: Step 1: Unable to export public key.", this);
                break;
            }
            
            // V3 activation is much simpler than V2. We need to just store device's public key
            // in Base64 format. The data encryption & protection is achieved by the ECIES.
            result.devicePublicKey = ad->devicePublicKeyData.base64String();
            
            // Finally, everything is OK
            error_code = EC_Ok;
            
        } while (false);
        
        if (error_code == EC_Ok) {
            // Keep activation data for other steps
            _ad = ad;
            changeState(SS_Activation1);
        } else {
            // Activation failed, delete AD structure
            delete ad;
        }
        return error_code;
    }
    
    ErrorCode Session::validateActivationResponse(const ActivationStep2Param & param, ActivationStep2Result & result)
    {
        LOCK_GUARD();
        // Validate state & parameters
        if (!hasPendingActivation() || _state != SS_Activation1) {
            CC7_LOG("Session %p: Step 2: Called in wrong state.", this);
            return EC_WrongState;
        }
        if (param.activationId.empty() ||
            param.serverPublicKey.empty() ||
            param.ctrData.empty()) {
            CC7_LOG("Session %p: Step 2: Missing input parameter.", this);
            return EC_WrongParam;
        }
        
        auto error_code = EC_Encryption;
        do {
            // Validate (optional) recovery data
            if (!protocol::ValidateRecoveryData(param.activationRecovery)) {
                CC7_LOG("Session %p: Step 2: Invalid recovery data.", this);
                return EC_WrongParam;
            }
            // Validate CTR_DATA
            if (!_ad->ctrData.readFromBase64String(param.ctrData) || _ad->ctrData.size() != protocol::SIGNATURE_KEY_SIZE) {
                // Note that we treat all B64 decode failures as an encryption error.
                CC7_LOG("Session %p: Step 2: CTR_DATA is invalid.", this);
                break;
            }
            // Now try to import server's public key
            _ad->serverPublicKeyData.readFromBase64String(param.serverPublicKey);
            _ad->serverPublicKey = crypto::ECC_ImportPublicKey(nullptr, _ad->serverPublicKeyData);
            if (!_ad->serverPublicKey) {
                CC7_LOG("Session %p: Step 2: Server's public key is not valid.", this);
                break;
            }

            // Now we have all required information and can calculate ECDH shared secret
            _ad->masterSharedSecret = protocol::ReduceSharedSecret(crypto::ECDH_SharedSecret(_ad->serverPublicKey, _ad->devicePrivateKey));
            if (_ad->masterSharedSecret.size() != protocol::SIGNATURE_KEY_SIZE) {
                // Shared secret calculation failed. Probably on an allocation failure.
                CC7_LOG("Session %p: Step 2: Shared secret calculation failed.", this);
                break;
            }
            // So far so good, the last step is decimalization of device's public key
            result.activationFingerprint = protocol::CalculateActivationFingerprint(_ad->devicePublicKeyData, _ad->serverPublicKeyData, param.activationId, Version_Latest);
            if (result.activationFingerprint.empty()) {
                CC7_LOG("Session %p: Step 2: Unable to calculate activation fingerprint.", this);
                break;
            }
            
            // Everything is OK, keep other data for later
            _ad->activationId = param.activationId;
            _ad->recoveryData = param.activationRecovery;
            
            error_code = EC_Ok;
            
        } while (false);
        
        if (error_code == EC_Ok) {
            // Everything is OK, switch to Activation2 state
            changeState(SS_Activation2);
        } else {
            // Activation failed, reset the session
            resetSession();
        }
        return error_code;
    }
    
    ErrorCode Session::completeActivation(const SignatureUnlockKeys & keys)
    {
        LOCK_GUARD();
        // Validate state & parameters
        if (!hasPendingActivation() || _state != SS_Activation2) {
            CC7_LOG("Session %p: Step 3: Called in wrong state.", this);
            return EC_WrongState;
        }
        if (!protocol::ValidateUnlockKeys(keys, eek(), protocol::SF_FirstLock)) {
            CC7_LOG("Session %p: Step 3: Wrong signature protection keys.", this);
            return EC_WrongParam;
        }
        auto error_code = EC_Encryption;
        auto pd = new protocol::PersistentData();
        do {
            // Keep all required information in the PD
            pd->signatureCounter        = 0;
            pd->signatureCounterData    = _ad->ctrData;
            pd->activationId            = _ad->activationId;
            pd->passwordIterations      = protocol::PBKDF2_PASS_ITERATIONS;
            pd->passwordSalt            = crypto::GetRandomData(protocol::PBKDF2_SALT_SIZE, true);
            pd->devicePublicKey         = _ad->devicePublicKeyData;
            pd->serverPublicKey         = _ad->serverPublicKeyData;
            pd->flagsU32                = 0;
            // Keep information about external key usage in the flags
            pd->flags.usesExternalKey = eek() ? 1 : 0;
            // V3.1 activation, set counter byte to 0.
            pd->flags.hasSignatureCounterByte = 1;
            pd->signatureCounterByte = 0;
            
            // Derive all required keys from master shared secret.
            protocol::SignatureKeys plain_keys;
            cc7::ByteArray vault_key;
            if (!protocol::DeriveAllSecretKeys(plain_keys, vault_key, _ad->masterSharedSecret)) {
                CC7_LOG("Session %p: Step 3: Unable to derive secret keys.", this);
                break;
            }
            protocol::SignatureUnlockKeysReq lock_request(protocol::SF_FirstLock, &keys, eek(), &pd->passwordSalt, pd->passwordIterations);
            if (!protocol::LockSignatureKeys(pd->sk, plain_keys, lock_request)) {
                CC7_LOG("Session %p: Step 3: Unable to protect secret keys.", this);
                break;
            }
            
            cc7::ByteArray device_private_key_data = crypto::ECC_ExportPrivateKey(_ad->devicePrivateKey);
            if (device_private_key_data.empty()) {
                CC7_LOG("Session %p: Step 3: Device private key export failed.", this);
                break;
            }
            pd->cDevicePrivateKey = crypto::AES_CBC_Encrypt_Padding(vault_key, protocol::ZERO_IV, device_private_key_data);
            if (pd->cDevicePrivateKey.empty()) {
                CC7_LOG("Session %p: Step 3: Unable to encrypt device private key.", this);
                break;
            }
            if (!protocol::SerializeRecoveryData(_ad->recoveryData, vault_key, pd->cRecoveryData)) {
                CC7_LOG("Session %p: Step 3: Unable to encrypt recovery data.", this);
                break;
            }
            
            // Final step is PD validation. If this step fails, then there's an internal problem.
            if (!protocol::ValidatePersistentData(*pd)) {
                CC7_LOG("Session %p: Step 3: Persistent data is invalid.", this);
                break;
            }
            
            // Everything is OK.
            error_code = EC_Ok;
            
        } while (false);
        
        if (error_code == EC_Ok) {
            // Everything is OK, commit new persistent data with a Activated state.
            commitNewPersistentState(pd, SS_Activated);
        } else {
            // An error occured, rollback everything to state before the activation
            commitNewPersistentState(pd, SS_Empty);
        }
        return error_code;
    }
    
    
    
    // MARK: - Status -
    
    ErrorCode Session::decodeActivationStatus(const EncryptedActivationStatus & enc_status, const SignatureUnlockKeys & keys, ActivationStatus & status) const
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: Status: Called in wrong state.", this);
            return EC_WrongState;
        }
        if (enc_status.challenge.empty() || enc_status.encryptedStatusBlob.empty() || enc_status.nonce.empty()) {
            CC7_LOG("Session %p: Status: All parameters are required in EncryptedActivationStatus.", this);
            return EC_WrongParam;
        }
        protocol::SignatureKeys signature_keys;
        protocol::SignatureUnlockKeysReq unlock_request(protocol::SF_Transport, &keys, eek(), nullptr, 0);
        if (!protocol::UnlockSignatureKeys(signature_keys, _pd->sk, unlock_request)) {
            CC7_LOG("Session %p: Status: You have to provide valid possession key.", this);
            return EC_WrongParam;
        }
        // Decode blob from B64 string
        cc7::ByteArray encrypted_status_blob;
        cc7::ByteArray status_nonce;
        cc7::ByteArray status_challenge;
        bool result = encrypted_status_blob.readFromBase64String(enc_status.encryptedStatusBlob);
        result = result && status_challenge.readFromBase64String(enc_status.challenge);
        result = result && status_nonce.readFromBase64String(enc_status.nonce);
        if (!result) {
            return EC_Encryption;
        }
        if (EC_Ok != protocol::DecryptEncryptedStatusBlob(encrypted_status_blob, status_challenge, status_nonce, signature_keys.transportKey, status)) {
            return EC_Encryption;
        }
        // Try to synchronize local counter
        status.counterState     = trySynchronizeCounter(status, signature_keys.transportKey);
        // If counter's state is invalid, then set state to "deadlock".
        if (status.counterState == ActivationStatus::Counter_Invalid) {
            status.state = ActivationStatus::Deadlock;
        }
        return EC_Ok;
    }
    
    ActivationStatus::CounterState Session::trySynchronizeCounter(const ActivationStatus & status, const cc7::ByteRange & transport_key) const
    {
        // If activation is still in V2 version, then we cannot determine counter's status.
        // In this case, it's OK to set Counter_OK.
        if (status.currentVersion == ActivationStatus::V2) {
            return ActivationStatus::Counter_OK;
        }
        
        const int look_ahead_window = status.lookAheadCount;
        const bool has_ctr_byte = _pd->flags.hasSignatureCounterByte;
        
        // At first, try to check whether the counter hash is OK
        auto local_ctr_data = _pd->signatureCounterData;
        auto hash_distance = protocol::CalculateHashCounterDistance(local_ctr_data, status.ctrDataHash, transport_key, look_ahead_window);
        if (!has_ctr_byte) {
            // We don't have captured counter byte yet, so test whether the hash is OK and if yes, then keep the received byte.
            if (hash_distance == 0) {
                // Everything's OK, keep received byte in persistent data and suggest save the session's state.
                _pd->flags.hasSignatureCounterByte = 1;
                _pd->signatureCounterByte = status.ctrByte;
                return ActivationStatus::Counter_Updated;
            }
            // Otherwise it's not possible to determine whether the counter's OK. We have to wait to sync counters
            // in the next regular signature calculation. In this case, we must pretend that everything's OK.
            return ActivationStatus::Counter_OK;
        }
        
        // Counter byte is available, so it's possible to estimate distance between the counters.
        // Negative 'byte_distance' means that the server is ahead. On opposite to that, positive value indicates
        // that the client's ahead.
        auto byte_distance = protocol::CalculateDistanceBetweenByteCounters(_pd->signatureCounterByte, status.ctrByte);
        if (hash_distance == 0 && byte_distance == 0) {
            // Everything's OK.
            return ActivationStatus::Counter_OK;
        }
        if (byte_distance > 0 && hash_distance == -1) {
            // Client's ahead. Determine for how much and decide the synchronization result.
            if (byte_distance > look_ahead_window) {
                // We cannot recover from this state. Client is too much ahead against the server.
                return ActivationStatus::Counter_Invalid;
            }
            if (byte_distance > look_ahead_window / 2) {
                // The local counter is more than half the allowed interval ahead to server.
                // It's recommended to calculate some signature soon.
                return ActivationStatus::Counter_CalculateSignature;
            }
            // Counter will be synchronized automatically
            return ActivationStatus::Counter_OK;
        }
        if (-byte_distance == hash_distance) {
            // hash distance is always greater than 0, but byte distance is negative in case that server's ahead.
            // We have last matched CTR_DATA value in local_ctr_data variable.
            _pd->signatureCounterData = local_ctr_data;
            _pd->signatureCounterByte = status.ctrByte;
            // Report that persistent data should be saved now.
            return ActivationStatus::Counter_Updated;
        }
        // Looks like that counters cannot be synchronized and the activation is technically blocked.
        return ActivationStatus::Counter_Invalid;
    }
    
    
    // MARK: - Data signing -
    
    cc7::ByteArray Session::prepareKeyValueMapForDataSigning(const std::map<std::string, std::string> & map)
    {
        // Create a vector of keys
        std::vector<const std::string *> keys;
        keys.reserve(map.size());
        size_t expected_result_size = 0;
        for (auto && kvpair : map) {
            expected_result_size += 2 + kvpair.first.length() + kvpair.second.length();
            keys.push_back(&kvpair.first);
        }
        // Sort that keys
        std::sort(keys.begin(), keys.end(), [](const std::string * a, const std::string * b) {
            return a->compare(*b) < 0;
        });
        // Concat sorted keys & values into: 'key1=value1&keyN=valueN' byte blob
        cc7::ByteArray result;
        result.reserve(expected_result_size);
        for (auto && key_ptr : keys) {
            const std::string & key   = *key_ptr;
            const std::string & value = map.find(key)->second;
            if (!result.empty()) {
                result.append('&');
            }
            result.append(utils::ConvertStringToUrlEncodedData(key));
            result.append('=');
            result.append(utils::ConvertStringToUrlEncodedData(value));
        }
        return result;
    }
        
    ErrorCode Session::signHTTPRequestData(const HTTPRequestData & request,
                                           const SignatureUnlockKeys & keys, SignatureFactor signature_factor,
                                           HTTPRequestDataSignature & out)
    {
        LOCK_GUARD();
        // Validate session's state & parameters
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: Sign: There's no valid activation.", this);
            return EC_WrongState;
        }
        if (!request.hasValidData()) {
            CC7_LOG("Session %p: Sign: Wrong request data.", this);
            return EC_WrongParam;
        }
        out.factor = protocol::ConvertSignatureFactorToString(signature_factor);
        if (out.factor.empty()) {
            CC7_LOG("Session %p: Sign: Wrong signature factor 0x%04x.", this, signature_factor);
            return EC_WrongParam;
        }
        // Check combination of offlineNonce & vaultUnlock.
        if (request.isOfflineRequest() && hasPendingProtocolUpgrade()) {
            CC7_LOG("Session %p: Sign: Offline signature is not available during the pending protocol upgrade.", this);
            return EC_WrongState;
        }
        
        // Re-seed OpenSSL's PRNG.
        crypto::ReseedPRNG();
        
        // Get NONCE from request structure, or generate a new one.
        cc7::ByteArray nonce;
        if (!request.isOfflineRequest()) {
            nonce = crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE, true);
            out.nonce = nonce.base64String();
        } else {
            if (!cc7::Base64_Decode(request.offlineNonce, 0, nonce)) {
                CC7_LOG("Session %p: Sign: request.offlineNonce is invalid.", this);
                return EC_Encryption;
            }
            out.nonce = request.offlineNonce;   // already in valid Base64 format
        }
        
        // Unlock keys. This also validates whether the provided unlock keys are present or not.
        protocol::SignatureKeys plain_keys;
        protocol::SignatureUnlockKeysReq unlock_request(signature_factor, &keys, eek(), &_pd->passwordSalt, _pd->passwordIterations);
        if (!protocol::UnlockSignatureKeys(plain_keys, _pd->sk, unlock_request)) {
            CC7_LOG("Session %p: Sign: Unable to unlock signature keys.", this);
            return EC_Encryption;
        }
        
        // Normalize data and calculate signature
        const std::string & app_secret = request.isOfflineRequest() ? protocol::PA_OFFLINE_APP_SECRET : _setup.applicationSecret;
        cc7::ByteArray data = protocol::NormalizeDataForSignature(request.method, request.uri, out.nonce, request.body, app_secret);
        cc7::ByteArray ctr_data = _pd->isV3() ? _pd->signatureCounterData : protocol::SignatureCounterToData(_pd->signatureCounter);
        const bool base64_sig_format = !request.isOfflineRequest() && _pd->isV3();
        out.signature = protocol::CalculateSignature(plain_keys, signature_factor, ctr_data, data, base64_sig_format, request.offlineSignatureLength);
        if (out.signature.empty()) {
            CC7_LOG("Session %p: Sign: Signature calculation failed.", this);
            return EC_Encryption;
        }
        
        // Move counter forward
        protocol::CalculateNextCounterValue(*_pd);
        
        // Fill the rest of values to out structure
        out.version         = Version_GetMaxSupportedHttpProtocolVersion(_pd->protocolVersion());
        out.activationId    = _pd->activationId;
        out.applicationKey  = request.isOfflineRequest() ? protocol::PA_OFFLINE_APP_SECRET : _setup.applicationKey;
        
        return EC_Ok;
    }
    
    const std::string & Session::httpAuthHeaderName() const
    {
        return protocol::PA_AUTH_HEADER_NAME;
    }
    
    ErrorCode Session::verifyServerSignedData(const SignedData & data) const
    {
        LOCK_GUARD();
        if (!hasValidSetup()) {
            CC7_LOG("Session %p: ServerSig: Session has no valid setup.", this);
            return EC_WrongState;
        }
        bool use_master_server_key = data.signingKey == SignedData::ECDSA_MasterServerKey;
        if (!use_master_server_key && !hasValidActivation()) {
            CC7_LOG("Session %p: ServerSig: There's no valid activation.", this);
            return EC_WrongState;
        }
        if (data.signature.empty()) {
            CC7_LOG("Session %p: ServerSig: The signature is empty.", this);
            return EC_WrongParam;
        }
        // Import public key
        bool success = false;
        crypto::BNContext ctx;
        EC_KEY * ec_public_key;
        if (use_master_server_key) {
            // Import master server public key
            ec_public_key = crypto::ECC_ImportPublicKeyFromB64(nullptr, _setup.masterServerPublicKey, ctx);
        } else {
            // Import server public key, which is personalized and associated with this session.
            ec_public_key = crypto::ECC_ImportPublicKey(nullptr, _pd->serverPublicKey);
        }
        if (nullptr != ec_public_key) {
            // validate signature
            if (data.signatureFormat == SignedData::ECDSA_JOSE) {
                // Convert signature from JOSE to DER first.
                success = crypto::ECDSA_ValidateSignature(data.data, crypto::ECDSA_JOSEtoDER(data.signature), ec_public_key);
            } else {
                // No signature conversion required.
                success = crypto::ECDSA_ValidateSignature(data.data, data.signature, ec_public_key);
            }
            //
        } else {
            CC7_LOG("Session %p: ServerSig: %s public key is invalid.", this, use_master_server_key ? "Master server" : "Server");
        }
        // Free allocated OpenSSL resources
        EC_KEY_free(ec_public_key);
        
        return success ? EC_Ok : EC_Encryption;
    }
    
    // MARK: - Signature keys management -
    
    ErrorCode Session::changeUserPassword(const cc7::ByteRange & old_password, const cc7::ByteRange & new_password)
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: PasswordChange: There's no valid activation.", this);
            return EC_WrongState;
        }
        
        // Prepare lock / unlock structures. In this one particular case session keeps these
        // structures hidden in implementation and allows you to use password directly.
        
        SignatureUnlockKeys old_keys;
        old_keys.userPassword = old_password;
        SignatureUnlockKeys new_keys;
        new_keys.userPassword = new_password;
        
        // Unlock knowledge key with using old password
        protocol::SignatureKeys plain_keys;
        protocol::SignatureUnlockKeysReq unlock_request(SF_Knowledge, &old_keys, eek(), &_pd->passwordSalt, _pd->passwordIterations);
        if (false == protocol::UnlockSignatureKeys(plain_keys, _pd->sk, unlock_request)) {
            return EC_Encryption;
        }
        
        // Generate new salt and protect knowledge key with a new password
        const cc7::U32 new_iterations_count = protocol::PBKDF2_PASS_ITERATIONS;
        cc7::ByteArray new_salt = crypto::GetRandomData(protocol::PBKDF2_SALT_SIZE, true);
        protocol::SignatureKeys encrypted_keys;
        protocol::SignatureUnlockKeysReq lock_request(SF_Knowledge, &new_keys, eek(), &new_salt, new_iterations_count);
        if (false == protocol::LockSignatureKeys(encrypted_keys, plain_keys, lock_request)) {
            return EC_Encryption;
        }

        // Store change to the PD and return success
        _pd->sk.knowledgeKey    = encrypted_keys.knowledgeKey;
        _pd->passwordSalt       = new_salt;
        _pd->passwordIterations = new_iterations_count;
        
        return EC_Ok;
    }

    ErrorCode Session::addBiometryFactor(const std::string & c_vault_key, const SignatureUnlockKeys & keys)
    {
        LOCK_GUARD();
        if (keys.biometryUnlockKey.empty()) {
            CC7_LOG("Session %p: addBiometryKey: The required biometryUnlockKey is missing.", this);
            return EC_WrongParam;
        }
        
        cc7::ByteArray vault_key;
        ErrorCode code = decryptVaultKey(c_vault_key, keys, vault_key);
        if (code != EC_Ok) {
            return code;
        }
        if (!_pd->sk.biometryKey.empty()) {
            CC7_LOG("Session %p: WARNING: There's already an existing biometry key.", this);
        }

        // Ok, we have vault key and now we can decrypt stored device's private key.
        crypto::BNContext ctx;
        EC_KEY * device_private_key = nullptr;
        EC_KEY * server_public_key  = nullptr;
        code = EC_Encryption;
        
        do {
            // Decrypt device's private key
            cc7::ByteArray device_private_key_data = crypto::AES_CBC_Decrypt_Padding(vault_key, protocol::ZERO_IV, _pd->cDevicePrivateKey);
            if (device_private_key_data.empty()) {
                // Well, if the key decryption fails here then it seems that we have a problem in vault_key computation.
                // Error at this point means that we're not able to deduce KEY_ENCRYPTION_VAULT_TRANSPORT correctly.
                break;
            }
            // Import device's private & server's public key
            device_private_key = crypto::ECC_ImportPrivateKey(nullptr, device_private_key_data, ctx);
            server_public_key  = crypto::ECC_ImportPublicKey(nullptr, _pd->serverPublicKey, ctx);
            cc7::ByteArray master_secret = protocol::ReduceSharedSecret(crypto::ECDH_SharedSecret(server_public_key, device_private_key));
            if (master_secret.empty()) {
                break;
            }
            // ECDH operation succeeded and therefore we can derive a key for biometry signature factor.
            protocol::SignatureKeys plain;
            plain.usesExternalKey = eek() != nullptr;
            cc7::ByteArray test_vault_key;
            if (!protocol::DeriveAllSecretKeys(plain, test_vault_key, master_secret)) {
                break;
            }
            if (test_vault_key != vault_key) {
                // Strange, derived vault key is different to the decrypted one.
                break;
            }
            protocol::SignatureUnlockKeysReq lock_request(SF_Biometry, &keys, eek(), nullptr, 0);
            if (!protocol::LockSignatureKeys(_pd->sk, plain, lock_request)) {
                break;
            }
            // Everything looks fine
            code = EC_Ok;

        } while (false);

        EC_KEY_free(device_private_key);
        EC_KEY_free(server_public_key);

        return code;
    }
    
    ErrorCode Session::hasBiometryFactor(bool &hasBiometryFactor) const
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: hasBiometryFactor: There's no valid activation.", this);
            hasBiometryFactor = false;
            return EC_WrongState;
        }
        hasBiometryFactor = !_pd->sk.biometryKey.empty();
        return EC_Ok;
    }
    
    ErrorCode Session::removeBiometryFactor()
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: removeBiometryKey: There's no valid activation.", this);
            return EC_WrongState;
        }
        if (_pd->sk.biometryKey.empty()) {
            CC7_LOG("Session %p: WARNING: The biometry key is not available.", this);
        }

        // Clear encrypted biometry key and reset waiting for vault flag.
        _pd->sk.biometryKey.clear();
        return EC_Ok;
    }
    
    
    // MARK: - Vault operations -
    
    ErrorCode Session::deriveCryptographicKeyFromVaultKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys,
                                                          cc7::U64 key_index, cc7::ByteArray & out_key)
    {
        LOCK_GUARD();
        cc7::ByteArray vault_key;
        ErrorCode code = decryptVaultKey(c_vault_key, keys, vault_key);
        if (code != EC_Ok) {
            return code;
        }
        out_key = protocol::DeriveSecretKey(vault_key, key_index);
        if (out_key.empty()) {
            return EC_Encryption;
        }
        return EC_Ok;
    }
    
    ErrorCode Session::signDataWithDevicePrivateKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys,
                                                    const cc7::ByteRange & in_data, SignedData::SignatureFormat out_format,
                                                    cc7::ByteArray & out_signature)
    {
        LOCK_GUARD();
        cc7::ByteArray vault_key;
        ErrorCode code = decryptVaultKey(c_vault_key, keys, vault_key);
        if (code != EC_Ok) {
            return code;
        }
        
        // Ok, we have vault key and now we can decrypt stored device's private key.
        crypto::BNContext ctx;
        EC_KEY * device_private_key = nullptr;
        code = EC_Encryption;
        
        do {
            // Decrypt device's private key
            cc7::ByteArray device_private_key_data = crypto::AES_CBC_Decrypt_Padding(vault_key, protocol::ZERO_IV, _pd->cDevicePrivateKey);
            if (device_private_key_data.empty()) {
                // Well, if the key decryption fails here then it seems that we have a problem in vault_key computation.
                // Error at this point means that we're not able to deduce KEY_ENCRYPTION_VAULT_TRANSPORT correctly.
                break;
            }
            // Import device's private key & calculate signature
            device_private_key = crypto::ECC_ImportPrivateKey(nullptr, device_private_key_data, ctx);
            if (!crypto::ECDSA_ComputeSignature(in_data, device_private_key, out_signature)) {
                // Signature calculation failed.
                break;
            }
            if (out_format == SignedData::ECDSA_JOSE) {
                out_signature = crypto::ECDSA_DERtoJOSE(out_signature);
                if (out_signature.empty()) {
                    // Conversion to JOSE format failed.
                    break;
                }
            }
            code = EC_Ok;
        } while (false);
        
        EC_KEY_free(device_private_key);
        
        return code;
    }
    
    ErrorCode Session::decryptVaultKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys, cc7::ByteArray & out_key)
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: Vault: There's no valid activation.", this);
            return EC_WrongState;
        }

        // Check if there's encrypted vault key and if yes, try to decode from B64
        if (c_vault_key.empty()) {
            CC7_LOG("Session %p: Vault: Missing encrypted vault key.", this);
            return EC_WrongParam;
        }
        cc7::ByteArray encrypted_vault_key;
        bool bResult = encrypted_vault_key.readFromBase64String(c_vault_key);
        if (!bResult || encrypted_vault_key.empty()) {
            // Treat wrong B64 format as attack on the protocol.
            CC7_LOG("Session %p: Vault: The provided vault key is wrong.", this);
            return EC_Encryption;
        }
        // Unlock transport key
        protocol::SignatureKeys plain;
        protocol::SignatureUnlockKeysReq unlock_request(protocol::SF_Transport, &keys, eek(), nullptr, 0);
        if (false == protocol::UnlockSignatureKeys(plain, _pd->sk, unlock_request)) {
            CC7_LOG("Session %p: Vault: You have to provide possession key.", this);
            return EC_WrongParam;
        }
        // V3: Vault key is now simply encrypted with KEY_TRANSPORT
        out_key = crypto::AES_CBC_Decrypt_Padding(plain.transportKey, protocol::ZERO_IV, encrypted_vault_key);
        if (out_key.size() != protocol::VAULT_KEY_SIZE) {
            return EC_Encryption;
        }
        return EC_Ok;
    }
    

    
    // MARK: - Utilities for generic keys -
    
    cc7::ByteArray Session::normalizeSignatureUnlockKeyFromData(const cc7::ByteRange & any_data)
    {
        cc7::ByteArray key = crypto::SHA256(any_data);
        key.resize(protocol::SIGNATURE_KEY_SIZE);
        return key;
    }
    
    cc7::ByteArray Session::generateSignatureUnlockKey()
    {
        return crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE, true);
    }
    
    
    
    // MARK: - External encryption key -
    
    bool Session::hasExternalEncryptionKey() const
    {
        LOCK_GUARD();
        return eek() != nullptr;
    }
    
    ErrorCode Session::setExternalEncryptionKey(const cc7::ByteRange & eek)
    {
        LOCK_GUARD();
        if (hasExternalEncryptionKey()) {
            if (_setup.externalEncryptionKey == eek) {
                return EC_Ok;
            }
            CC7_LOG("Session %p: EEK: Setting different EEK is not allowed.", this);
        } else {
            if (hasValidActivation()) {
                // If session is activated, then we can check whether the EEK is really used or not.
                if (!_pd->flags.usesExternalKey) {
                    // Setting EEK while session doesn't use it is invalid. You'll not able to sign data anymore.
                    CC7_LOG("Session %p: EEK: Activated session doesn't use EEK.", this);
                    return EC_WrongState;
                }
            }
            if (_setup.externalEncryptionKey.empty()) {
                if (eek.size() == protocol::SIGNATURE_KEY_SIZE) {
                    _setup.externalEncryptionKey = eek;
                    return EC_Ok;
                } else {
                    CC7_LOG("Session %p: EEK: Wrong size of EEK.", this);
                }
            } else {
                CC7_LOG("Session %p: EEK: Session has EEK but is already invalid.", this);
            }
        }
        return EC_WrongParam;
    }
    
    ErrorCode Session::addExternalEncryptionKey(const cc7::ByteArray &eek)
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: EEK: Session has no valid activation.", this);
            return EC_WrongState;
        }
        if (_pd->flags.usesExternalKey) {
            CC7_LOG("Session %p: EEK: Session is already using EEK.", this);
            return EC_WrongState;
        }
        if (eek.size() != protocol::SIGNATURE_KEY_SIZE) {
            CC7_LOG("Session %p: EEK: The provided key has wrong size.", this);
            return EC_WrongParam;
        }
        // Add EEK protection
        if (!protocol::ProtectSignatureKeysWithEEK(_pd->sk, eek, true)) {
            return EC_Encryption;
        }
        _setup.externalEncryptionKey = eek;
        _pd->flags.usesExternalKey = true;
        return EC_Ok;
    }
    
    ErrorCode Session::removeExternalEncryptionKey()
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: EEK: Session has no valid activation.", this);
            return EC_WrongState;
        }
        if (!_pd->flags.usesExternalKey) {
            CC7_LOG("Session %p: EEK: Session is not using EEK.", this);
            return EC_WrongState;
        }
        if (!hasExternalEncryptionKey()) {
            CC7_LOG("Session %p: EEK: The EEK is not set.", this);
            return EC_WrongState;
        }
        // Remove EEK protection
        if (!protocol::ProtectSignatureKeysWithEEK(_pd->sk, _setup.externalEncryptionKey, false)) {
            return EC_Encryption;
        }
        _setup.externalEncryptionKey.clear();
        _pd->flags.usesExternalKey = false;
        return EC_Ok;
    }
    
    // Private EEK getter
    
    const cc7::ByteArray * Session::eek() const
    {
        if (hasValidSetup() && _setup.externalEncryptionKey.size() == protocol::SIGNATURE_KEY_SIZE) {
            return &_setup.externalEncryptionKey;
        }
        return nullptr;
    }
    
    // MARK: - ECIES Factory -
    
    ErrorCode Session::getEciesEncryptor(ECIESEncryptorScope scope, const SignatureUnlockKeys & keys, const cc7::ByteRange & sharedInfo1, ECIESEncryptor & out_encryptor) const
    {
        LOCK_GUARD();
        if (!hasValidSetup()) {
            CC7_LOG("Session %p: ECIES: Session has no valid setup.", this);
            return EC_WrongState;
        }
        // Other parameters for ECIES encryptor
        cc7::ByteArray ecPublicKey;
        cc7::ByteArray sharedInfo2;
        //
        if (scope == ECIES_ApplicationScope) {
            // For "application" scope, the setup is quite simple.
            // We have to just compute hash from APP_SECRET (as is) and use
            // the master server public key.
            sharedInfo2 = crypto::SHA256(cc7::MakeRange(_setup.applicationSecret));
            ecPublicKey = cc7::FromBase64String(_setup.masterServerPublicKey);
            //
        } else if (scope == ECIES_ActivationScope) {
            // For the "activation" scope, we need to at first validate whether there's
            // some activation.
            if (!hasValidActivation()) {
                CC7_LOG("Session %p: ECIES: Session has no valid activation.", this);
                return EC_WrongState;
            }
            // Acquire the transport key
            protocol::SignatureKeys plain_keys;
            protocol::SignatureUnlockKeysReq unlock_request(protocol::SF_Transport, &keys, eek(), &_pd->passwordSalt, _pd->passwordIterations);
            if (!protocol::UnlockSignatureKeys(plain_keys, _pd->sk, unlock_request)) {
                CC7_LOG("Session %p: ECIES: You have to provide valid possession key.", this);
                return EC_Encryption;
            }
            // The sharedInfo2 is defined as HMAC_SHA256(key: KEY_TRANSPORT, data: APP_SECRET)
            // We need to also use the server's public key as EC public key.
            sharedInfo2 = crypto::HMAC_SHA256(cc7::MakeRange(_setup.applicationSecret), plain_keys.transportKey);
            ecPublicKey = _pd->serverPublicKey;
            //
        } else {
            // Scope is not known
            CC7_LOG("Session %p: ECIES: Unsupported scope.", this);
            return EC_WrongParam;
        }
        // Now construct the encryptor with prepared setup.
        out_encryptor = ECIESEncryptor(ecPublicKey, sharedInfo1, sharedInfo2);
        return EC_Ok;
    }
    
    // MARK: - Protocol upgrade -
    
    ErrorCode Session::startProtocolUpgrade()
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: StartUpgrade: Session has no valid activation.", this);
            return EC_WrongState;
        }
        switch (_pd->protocolVersion()) {
            case Version_V2:
                _pd->flags.pendingUpgradeVersion = Version_V3;
                return EC_Ok;
            default:
                break;
        }
        CC7_LOG("Session %p: StartUpgrade: Session is already in V3.", this);
        return EC_WrongState;
    }
    
    
    Version Session::pendingProtocolUpgradeVersion() const
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            return Version_NA;
        }
        return (Version) _pd->flags.pendingUpgradeVersion;
    }
    
    
    ErrorCode Session::applyProtocolUpgradeData(const ProtocolUpgradeData & upgrade_data)
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: ApplyUpgradeData: Session has no valid activation.", this);
            return EC_WrongState;
        }
        switch (_pd->protocolVersion()) {
            case Version_V2:
            {
                if (_pd->flags.pendingUpgradeVersion != Version_V3) {
                    CC7_LOG("Session %p: ApplyUpgradeData: Upgrade to V3 was not properly started.", this);
                    return EC_WrongState;
                }
                cc7::ByteArray ctr_data;
                if (!cc7::Base64_Decode(upgrade_data.toV3.ctrData, 0, ctr_data) || ctr_data.size() != protocol::SIGNATURE_KEY_SIZE) {
                    CC7_LOG("Session %p: ApplyUpgradeData: Wrong V3 upgrade data.", this);
                    return EC_WrongParam;
                }
                // Everything looks fine, we can commit new data.
                _pd->signatureCounterData = ctr_data;
                _pd->signatureCounter = 0;
                _pd->flags.waitingForVaultUnlock = 0;
                // V3.1: Despite the fact that we still have a local counter, it might be still out of the sync.
                //       So, mark the counter byte as invalid, just like we do for migration from V3 to V3.1.
                _pd->flags.hasSignatureCounterByte = 0;
                return EC_Ok;
            }
            default:
                break;
        }
        CC7_LOG("Session %p: ApplyUpgradeData: Session is already in V3.", this);
        return EC_WrongState;
    }
    
    
    ErrorCode Session::finishProtocolUpgrade()
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: FinishUpgrade: Session has no valid activation.", this);
            return EC_WrongState;
        }
        switch (_pd->flags.pendingUpgradeVersion) {
            case Version_V3:
                if (_pd->protocolVersion() == Version_V3) {
                    // Upgrade to V3 succeeded.
                    _pd->flags.pendingUpgradeVersion = Version_NA;
                    return EC_Ok;
                }
                CC7_LOG("Session %p: FinishUpgrade: Upgrade to V3 is not finished yet.", this);
                break;
            default:
                break;
        }
        return EC_WrongState;
    }


    // MARK: - Recovery code -
    
    bool Session::hasActivationRecoveryData() const
    {
        LOCK_GUARD();
        return hasValidActivation() && !_pd->cRecoveryData.empty();
    }
    
    
    ErrorCode Session::getActivationRecoveryData(const std::string & c_vault_key, const SignatureUnlockKeys & keys, RecoveryData & out_recovery_data)
    {
        LOCK_GUARD();
        if (!hasValidActivation()) {
            CC7_LOG("Session %p: RecoveryData: Session has no valid activation.", this);
            return EC_WrongState;
        }
        if (_pd->cRecoveryData.empty()) {
            CC7_LOG("Session %p: RecoveryData: Session has no recovery data available.", this);
            return EC_WrongState;
        }
        cc7::ByteArray vault_key;
        auto ec = decryptVaultKey(c_vault_key, keys, vault_key);
        if (ec == EC_Ok) {
            if (!protocol::DeserializeRecoveryData(_pd->cRecoveryData, vault_key, out_recovery_data)) {
                CC7_LOG("Session %p: RecoveryData: Cannot decrypt or deserialize recovery data.", this);
                ec = EC_Encryption;
            }
        }
        return ec;
    }
    
    // MARK: - Private methods -
    
    /*
     The function deletes _ad and commits new persistent state, which is represented
     by the combination of the parameters:
     
     | new_pd   | new_state    | Behavior
     -----------------------------------------------------------------
     | null     | any state    | Resets session to initial state
     | not-null | SS_Empty     | Resets session to initial state
     | not-null | SS_Activated | Keeps new PD and state
     ------------------------------------------------------------------------------
     
     All other combination of parameters leads to fallback state.
     */
    void Session::commitNewPersistentState(protocol::PersistentData *new_pd, Session::State new_state)
    {
        // At first, delete possible activation data. In all cases, commit must clear
        // any instance of activation data.
        delete _ad;
        _ad = nullptr;
        
        // The next structure is PersistentData. We have to delete possible previous instance
        // of PD and if state is correct, then keep the new one.
        delete _pd;
        if (new_pd != nullptr && new_state == SS_Activated) {
            // Ok, keep the new structure
            _pd = new_pd;
        } else {
            // Delete everything
            delete new_pd;
            _pd = new_pd = nullptr;
            // PD was not commited, so, we have to adjust new state.
            new_state = SS_Empty;
        }
        
        // Finally, change internal state of the session
        changeState(new_state);
    }
    
#ifdef ENABLE_CC7_LOG
    static const char * _StateName(Session::State st)
    {
        switch (st) {
            case Session::SS_Invalid:
                return "Invalid";
            case Session::SS_Empty:
                return "Empty";
            case Session::SS_Activated:
                return "Activated";
            case Session::SS_Activation1:
                return "Activation_1";
            case Session::SS_Activation2:
                return "Activation_2";
            default:
                return "Unknown!!";
        }
    }
#endif
    
    void Session::changeState(Session::State new_state)
    {
#ifdef ENABLE_CC7_LOG
        if (_state != new_state) {
            CC7_LOG("Session %p: Changing state  %s  ->   %s", this, _StateName(_state), _StateName(new_state));
        }
#endif
        if (CC7_CHECK(new_state >= SS_Empty, "Internal error. Changing to SS_Invalid is not allowed!")) {
            _state = new_state;
        }
    }
    
    
} // io::getlime::powerAuth
} // io::getlime
} // io
