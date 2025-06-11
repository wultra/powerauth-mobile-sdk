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

#include <cc7/crypto/NonceGenerator.h>

namespace powerAuth {
namespace crypto {

class ThreadSafeNonceGenerator : public cc7::crypto::NonceGenerator
{
public:
    static cc7::crypto::NonceGeneratorPtr getInstance(size_t nonce_size, std::shared_ptr<std::recursive_mutex> lock = nullptr);
    static cc7::crypto::NonceGeneratorPtr getInstance(cc7::crypto::NonceGeneratorPtr generator, std::shared_ptr<std::recursive_mutex> lock = nullptr);
    
    ThreadSafeNonceGenerator(cc7::crypto::NonceGeneratorPtr generator, std::shared_ptr<std::recursive_mutex> lock);
    
    size_t getNonceSize() const noexcept override;
    cc7::ByteArray getNonce() override;
    bool checkUniqueness(const cc7::ByteRange & nonce, bool remember) override;
    cc7::ByteArray saveState() const override;
    void restoreState(const cc7::ByteRange & saved_state) override;
    void resetSavedState() override;

private:
    const std::shared_ptr<std::recursive_mutex> _lock;
    const cc7::crypto::NonceGeneratorPtr _generator;
};

} // namespace crypto
} // namespace powerAuth
