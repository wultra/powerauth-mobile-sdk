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
    
    powerAuth::ConfigurationPtr configuration;
    
    std::string sdkConfiguration;
    cc7::crypto::KeyPairPtr legacyMasterKeyPair;
    cc7::crypto::KeyPairPtr ecdsaMasterKeyPair;
    cc7::crypto::KeyPairPtr mldsaMasterKeyPair;
    cc7::ByteArray deviceSpecificData;
    
    void reGenerateConfiguration(powerAuth::PowerAuthSpec::Algorithm algorithm)
    {
        auto instance_id = cc7::crypto::GetRandomData(8).base64();
        auto app_key    = cc7::crypto::GetRandomData(16);
        auto app_secret = cc7::crypto::GetRandomData(16);
        
        
        legacyMasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("P-256");
        ecdsaMasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("P-384");
        mldsaMasterKeyPair = cc7::crypto::KeyPair::generateKeyPair("ML-DSA-65");
        deviceSpecificData = cc7::crypto::GetRandomData(33);
        
        auto writer = cc7::utils::DataWriter();
        writer.writeByte(0x01);
        writer.writeData(app_key);
        writer.writeData(app_secret);
        
        writer.writeCount(3);
        // legacy
        writer.writeByte(0x01);
        writer.writeData(legacyMasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963));
        // ecdsa
        writer.writeByte(0x02);
        writer.writeData(ecdsaMasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963));
        // mldsa
        writer.writeByte(0x03);
        writer.writeData(mldsaMasterKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_SPKI));
        
        sdkConfiguration = writer.serializedData().base64();
        
        configuration = powerAuth::Configuration::Builder(sdkConfiguration)
                            .withAlgorithm(algorithm)
                            .withDeviceSpecificData(deviceSpecificData)
                            .withInstanceId(instance_id)
                            .build();
    }
};

} // namespace powerAuthTests
