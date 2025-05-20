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



class RequestEncryptor
{
public:
    
private:
    friend class ClientEncryptor;
    
    RequestEncryptor(const cc7::ByteRange& envelope_key, const cc7::crypto::NonceGeneratorPtr & nonce_generator);
    
};


class ClientEncryptor
{
public:
    ClientEncryptor(const cc7::ByteRange& shared_secret);
    
private:
    cc7::ByteArray _shared_secret;
    cc7::crypto::NonceGeneratorPtr _nonce_generator;
};

typedef std::shared_ptr<ClientEncryptor> ClientEncryptorPtr;




class ResponseEncryptor
{
public:
    
private:
    friend class ServerDecryptor;
};

class ServerDecryptor
{
public:
private:
    // Server encryptor actually doesn't generate noce.
    // We're using this only for testing noce uniqueness.
    cc7::crypto::NonceGeneratorPtr _nonce_generator;
};

typedef std::shared_ptr<ServerDecryptor> ClientDecryptorPtr;

} // namespace powerAuth
} // namespace getlime
} // namespace io
