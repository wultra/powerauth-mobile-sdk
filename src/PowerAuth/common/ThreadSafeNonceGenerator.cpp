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

#include "ThreadSafeNonceGenerator.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace common {

// MARK: - ThreadSafeNonceGenerator

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

NonceGeneratorPtr ThreadSafeNonceGenerator::getInstance(size_t nonce_size, std::shared_ptr<std::recursive_mutex> lock)
{
    return getInstance(DefaultNonceGenerator::getInstance(nonce_size), lock);
}

NonceGeneratorPtr ThreadSafeNonceGenerator::getInstance(NonceGeneratorPtr generator, std::shared_ptr<std::recursive_mutex> lock)
{
    return std::make_shared<ThreadSafeNonceGenerator>(generator, lock);
}

ThreadSafeNonceGenerator::ThreadSafeNonceGenerator(NonceGeneratorPtr generator, std::shared_ptr<std::recursive_mutex> lock) :
    _generator(generator),
    _lock(lock == nullptr ? std::make_shared<std::recursive_mutex>() : lock)
{
    if (generator == nullptr) {
        throw std::invalid_argument("generator parameter must not be null");
    }
}

size_t ThreadSafeNonceGenerator::getNonceSize() const noexcept
{
    LOCK_GUARD();
    return _generator->getNonceSize();
}

ByteArray ThreadSafeNonceGenerator::getNonce()
{
    LOCK_GUARD();
    return _generator->getNonce();
}

bool ThreadSafeNonceGenerator::checkUniqueness(const ByteRange & nonce, bool remember)
{
    LOCK_GUARD();
    return _generator->checkUniqueness(nonce, remember);
}

ByteArray ThreadSafeNonceGenerator::saveState() const
{
    LOCK_GUARD();
    return _generator->saveState();
}

void ThreadSafeNonceGenerator::restoreState(const ByteRange & saved_state)
{
    LOCK_GUARD();
    _generator->restoreState(saved_state);
}

void ThreadSafeNonceGenerator::resetSavedState()
{
    LOCK_GUARD();
    _generator->resetSavedState();
}

} // namespace common
} // namespace powerAuth
