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

#include <PowerAuth/PublicTypes.h>
#include <cc7/crypto/Crypto.h>

namespace io {
namespace getlime {
namespace powerAuth {

enum SharedSecretAlgorithm
{
    EC_P384,
    EC_P384_ML_L3
};

struct SharedSecretSpec
{
    SharedSecretAlgorithm   identifier;
    std::string             algorithm;
    std::string             derivation_label;
    
    static const SharedSecretSpec * specForAlgorithm(SharedSecretAlgorithm algorithm);
    static const SharedSecretSpec * specForAlgorithm(const std::string & algorithm);
};

typedef cc7::crypto::BaseObjectPtr SharedSecretContextPtr;

struct SharedSecretRequest
{
    std::string algorithm;
    std::string ecdhe;
    std::string mlkem;
};

struct SharedSecretResponse
{
    std::string ecdhe;
    std::string mlkem;
};

class SharedSecret : public cc7::crypto::BaseObject
{
public:
    static std::shared_ptr<SharedSecret> getInstance(SharedSecretAlgorithm algorithm);
    
    virtual std::pair<SharedSecretRequest, SharedSecretContextPtr> generateRequestCryptogram() const = 0;
    virtual std::pair<SharedSecretResponse, cc7::ByteArray> generateResponseCryptogram(const SharedSecretRequest & request) const = 0;
    virtual cc7::ByteArray computeSharedSecret(const SharedSecretContextPtr & context, const SharedSecretResponse & response) const = 0;
    
    // Serialization
    
    virtual SharedSecretContextPtr deserializeContext(const cc7::ByteRange & context_data) const = 0;
    virtual cc7::ByteArray serializeContext(const SharedSecretContextPtr & context) const = 0;

    // Tests
    
    virtual SharedSecretContextPtr importContextForTest(const std::map<std::string, std::string> & test_data) const = 0;
    virtual std::map<std::string, std::string> exportContextForTest(const SharedSecretContextPtr & context) const = 0;
};

typedef std::shared_ptr<SharedSecret> SharedSecretPtr;


} // io::getlime::powerAuth
} // io::getlime
} // io
