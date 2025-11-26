/*
 * Copyright 2025 Wultra s.r.o.
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

#pragma once

#include <PowerAuth/Configuration.h>
#include <cc7/utils/DataWriter.h>
#include <cc7/crypto/Random.h>

namespace powerAuthTests {

class ConfigurationGenerator
{
public:
    
    ConfigurationGenerator(powerAuth::PowerAuthSpec::Algorithm algorithm = powerAuth::PowerAuthSpec::EC_P384_ML_L3)
    {
        reGenerateConfiguration(algorithm);
    }
    
    powerAuth::PowerAuthSpec::Algorithm targetAlgorithm;
    powerAuth::ConfigurationPtr configuration;
    
    std::string sdkConfiguration;
    cc7::crypto::KeyPairPtr legacyMasterKeyPair;
    cc7::crypto::KeyPairPtr ecdsaMasterKeyPair;
    cc7::crypto::KeyPairPtr mldsa65MasterKeyPair;
    cc7::crypto::KeyPairPtr mldsa87MasterKeyPair;
    cc7::ByteArray deviceSpecificData;
    
    std::pair<cc7::crypto::KeyPairPtr, cc7::crypto::KeyPairPtr> masterKeyPairs;
        
    void reGenerateConfiguration(powerAuth::PowerAuthSpec::Algorithm algorithm)
    {
        auto instance_id = cc7::crypto::GetRandomData(8).base64();
        auto app_key    = cc7::crypto::GetRandomData(16);
        auto app_secret = cc7::crypto::GetRandomData(16);
        
        targetAlgorithm = algorithm;
        legacyMasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("P-256");
        ecdsaMasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("P-384");
        mldsa65MasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("ML-DSA-65");
        mldsa87MasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("ML-DSA-87");
        deviceSpecificData = cc7::crypto::GetRandomData(33);
        
        switch (algorithm) {
            case powerAuth::PowerAuthSpec::LEGACY_P256:
                masterKeyPairs = std::make_pair(legacyMasterKeyPair, nullptr);
                break;
            case powerAuth::PowerAuthSpec::EC_P384:
                masterKeyPairs = std::make_pair(ecdsaMasterKeyPair, nullptr);
                break;
            case powerAuth::PowerAuthSpec::EC_P384_ML_L3:
                masterKeyPairs = std::make_pair(ecdsaMasterKeyPair, mldsa65MasterKeyPair);
                break;
            case powerAuth::PowerAuthSpec::EC_P384_ML_L5:
                masterKeyPairs = std::make_pair(ecdsaMasterKeyPair, mldsa87MasterKeyPair);
                break;
            case powerAuth::PowerAuthSpec::ML_L3:
                masterKeyPairs = std::make_pair(mldsa65MasterKeyPair, nullptr);
                break;
            case powerAuth::PowerAuthSpec::ML_L5:
                masterKeyPairs = std::make_pair(mldsa87MasterKeyPair, nullptr);
                break;
            default:
                throw std::invalid_argument("Unsupported PowerAuhtSpec in ConfigurationGenerator");
        }
        
        auto writer = cc7::utils::DataWriter();
        writer.writeByte(0x01);
        writer.writeData(app_key);
        writer.writeData(app_secret);
        
        writer.writeCount(4);
        // legacy
        writer.writeByte(powerAuth::PowerAuthSpec::KEY_ID_P256);
        writer.writeData(legacyMasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963));
        // ecdsa
        writer.writeByte(powerAuth::PowerAuthSpec::KEY_ID_P384);
        writer.writeData(ecdsaMasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963));
        // mldsa65
        writer.writeByte(powerAuth::PowerAuthSpec::KEY_ID_MLDSA65);
        writer.writeData(mldsa65MasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_SPKI));
        // mldsa87
        writer.writeByte(powerAuth::PowerAuthSpec::KEY_ID_MLDSA87);
        writer.writeData(mldsa87MasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_SPKI));
        sdkConfiguration = writer.serializedData().base64();
        
        configuration = powerAuth::Configuration::Builder(sdkConfiguration, algorithm)
                            .withDeviceSpecificData(deviceSpecificData)
                            .withInstanceId(instance_id)
                            .build();
    }
};

} // namespace powerAuthTests
