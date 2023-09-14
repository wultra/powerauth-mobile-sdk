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
#include <cc7/Base64.h>
#include "protocol/Constants.h"
#include "utils/DataReader.h"
#include "utils/DataWriter.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
    //
    // MARK: - SessionSetup -
    //

    static const cc7::byte CONFIG_VER  = 0x01;
    static const cc7::byte P256_KEY_ID = 0x01;
    
    bool SessionSetup::loadFromConfiguration(const std::string & config)
    {
        auto reader = utils::DataReader(cc7::FromBase64String(config));
        cc7::byte data_version;
        if (!reader.readByte(data_version)) {
            return false;
        }
        if (data_version != CONFIG_VER) {
            return false;
        }
        cc7::ByteArray app_key, app_secret;
        if (!reader.readData(app_key, protocol::APPLICATION_KEY_SIZE) ||
            !reader.readData(app_secret, protocol::APPLICATION_SECRET_SIZE)) {
            return false;
        }
        size_t keys_count;
        if (!reader.readCount(keys_count)) {
            return false;
        }
        cc7::ByteArray p256key;
        while (keys_count-- > 0) {
            cc7::byte key_id;
            cc7::ByteArray key_data;
            if (!reader.readByte(key_id) || !reader.readData(key_data)) {
                return false;
            }
            if (key_id == P256_KEY_ID) {
                p256key = key_data;
            }
        }
        if (p256key.empty()) {
            return false;
        }
        // Finally, convert loaded values into setup structure
        applicationKey = app_key.base64String();
        applicationSecret = app_secret.base64String();
        masterServerPublicKey = p256key.base64String();
        return true;
    }

    std::string SessionSetup::saveConfiguration() const
    {
        auto writer = utils::DataWriter();
        writer.writeByte(CONFIG_VER);
        writer.writeData(cc7::FromBase64String(applicationKey));
        writer.writeData(cc7::FromBase64String(applicationSecret));
        writer.writeCount(1);
        writer.writeByte(P256_KEY_ID);
        writer.writeData(cc7::FromBase64String(masterServerPublicKey));
        return writer.serializedData().base64String();
    }

    //
    // MARK: - HTTPRequestData -
    //
    
    HTTPRequestData::HTTPRequestData() :
        offlineSignatureLength(protocol::DECIMAL_SIGNATURE_MAX_LENGTH)
    {
    }
    
    HTTPRequestData::HTTPRequestData(const cc7::ByteRange & body,
                                     const std::string & method,
                                     const std::string & uri) :
        body(body),
        method(method),
        uri(uri),
        offlineSignatureLength(protocol::DECIMAL_SIGNATURE_MAX_LENGTH)
    {
    }
    
    HTTPRequestData::HTTPRequestData(const cc7::ByteRange & body,
                                     const std::string & method,
                                     const std::string & uri,
                                     const std::string & offlineNonce,
                                     size_t offlineLength) :
        body(body),
        method(method),
        uri(uri),
        offlineNonce(offlineNonce),
        offlineSignatureLength(offlineLength)
    {
    }
    
    bool HTTPRequestData::hasValidData() const
    {
        if (method.empty() || uri.empty()) {
            return false;
        }
        if (!(method == "GET" || method == "POST" || method == "HEAD" || method == "PUT" || method == "DELETE")) {
            return false;
        }
        if (!offlineNonce.empty()) {
            if (offlineNonce.size() != protocol::OFFLINE_SIGNATURE_NONCE_LENGTH) {
                return false;
            }
            if (offlineSignatureLength < protocol::DECIMAL_SIGNATURE_MIN_LENGTH ||
                offlineSignatureLength > protocol::DECIMAL_SIGNATURE_MAX_LENGTH) {
                return false;
            }
        }
        return true;
    }
    
    bool HTTPRequestData::isOfflineRequest() const
    {
        return !offlineNonce.empty();
    }
    
    
    //
    // MARK: - HTTPRequestDataSignature -
    //
    
    std::string HTTPRequestDataSignature::buildAuthHeaderValue() const
    {
        const size_t out_size = activationId.length() + applicationKey.length() + nonce.length() + factor.length() + signature.length() +
                                version.length() + protocol::PA_AUTH_FRAGMENTS_LENGTH;
        std::string out;
        out.reserve(out_size);
        
        // Build header value
        out.assign(protocol::PA_AUTH_FRAGMENT_BEGIN_VERSION);
        out.append(version);
        out.append(protocol::PA_AUTH_FRAGMENT_ACTIVATION_ID);
        out.append(activationId);
        out.append(protocol::PA_AUTH_FRAGMENT_APPLICATION_KEY);
        out.append(applicationKey);
        out.append(protocol::PA_AUTH_FRAGMENT_NONCE);
        out.append(nonce);
        out.append(protocol::PA_AUTH_FRAGMENT_SIGNATURE_TYPE);
        out.append(factor);
        out.append(protocol::PA_AUTH_FRAGMENT_SIGNATURE);
        out.append(signature);
        out.append(protocol::PA_AUTH_FRAGMENT_END);
        
        return out;
    }

    
    //
    // MARK: - RecoveryData -
    //
    
    bool RecoveryData::isEmpty() const
    {
        return recoveryCode.empty() && puk.empty();
    }
    
    
    //
    // MARK: - ActivationStatus -
    //
    
    bool ActivationStatus::isProtocolUpgradeAvailable() const
    {
        if (state == Active) {
            if (currentVersion < upgradeVersion) {
                return upgradeVersion <= MaxSupported;
            }
        }
        return false;
    }
    
    bool ActivationStatus::isSignatureCalculationRecommended() const
    {
        if (state == Active) {
            return counterState == Counter_CalculateSignature;
        }
        return false;
    }
    
    bool ActivationStatus::needsSerializeSessionState() const
    {
        return counterState == Counter_Updated;
    }


    //
    // MARK: - Version -
    //

    std::string Version_GetMaxSupportedHttpProtocolVersion(Version protocol_version)
    {
        if (protocol_version == Version_NA) {
            protocol_version = Version_Latest;
        }
        switch (protocol_version) {
            case Version_V2: return protocol::PA_VERSION_V2;
            case Version_V3: return protocol::PA_VERSION_V3;
            default: break;
        }
        CC7_ASSERT(false, "Invalid protocol version");
        return protocol::PA_VERSION_V3;
    }
    
} // io::getlime::powerAuth
} // io::getlime
} // io
