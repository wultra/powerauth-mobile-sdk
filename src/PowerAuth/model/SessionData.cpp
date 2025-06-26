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

#include "SessionData.h"

namespace powerAuth {

SessionData::SessionData()
{
}

ProtocolVersion SessionData::getProtocolVersion() const noexcept
{
    if (_pd) {
        return _pd->getProtocolVersion();
    }
    // No persistent data available, so we assume that we run on the latest version.
    return Version_Latest;
}

bool SessionData::isModified() const noexcept
{
    return _pd ? _pd->isModified() : false;
}

void SessionData::setRegistrationData(RegistrationDataPtr &ptr)
{
    _rd = std::move(ptr);
    _pd = nullptr;
}

bool SessionData::hasRegistrationData() const noexcept
{
    return _rd != nullptr;
}

void SessionData::setPersistentData(PersistentDataPtr &ptr)
{
    _rd = nullptr;
    _pd = std::move(ptr);
}

bool SessionData::hasPersistentData() const noexcept
{
    return _pd != nullptr;
}

void SessionData::resetSessionData()
{
    _rd = nullptr;
    _pd = nullptr;
}

const RegistrationData& SessionData::registrationData() const
{
    if (!_rd) {
        throw Exception(EC_InternalError, "ActivationData not available");
    }
    return *_rd;
}

RegistrationData& SessionData::registrationData()
{
    if (!_rd) {
        throw Exception(EC_InternalError, "ActivationData not available");
    }
    return *_rd;
}

const PersistentData& SessionData::persistentData() const
{
    if (!_pd) {
        throw Exception(EC_InternalError, "PersistentData not available");
    }
    return *_pd;
}

PersistentData& SessionData::persistentData()
{
    if (!_pd) {
        throw Exception(EC_InternalError, "PersistentData not available");
    }
    return *_pd;
}

// Serialization

static const cc7::byte SD_TAG   = 'P';
static const cc7::byte SD_VER1  = 'A';                // SDK 0.x.y - 1.x.y

static const cc7::byte SD_VER1_FLAG_NONE  = 0;        // No additional data included
static const cc7::byte SD_VER1_FLAG_PD    = 1 << 1;   // PersistentData included



cc7::ByteArray SessionData::serialize() const
{
    bool has_pd = hasPersistentData();
    cc7::utils::DataWriter writer;
    writer.openVersion(SD_TAG, SD_VER1);
    writer.writeByte(has_pd ? SD_VER1_FLAG_PD : SD_VER1_FLAG_NONE);
    if (has_pd) {
        _pd->serialize(writer);
    }
    writer.closeVersion();
    return writer.serializedData();
}

void SessionData::deserialize(const cc7::ByteRange& serialized_data)
{
    cc7::byte flags = 0;
    cc7::utils::DataReader reader(serialized_data, false);
    if (!reader.openVersion(SD_TAG, SD_VER1, SD_VER1) || !reader.readByte(flags)) {
        throw Exception(EC_InvalidData, "Unknown SessionData format");
    }
    if (flags & SD_VER1_FLAG_PD) {
        auto pd = PersistentData::deserialize(reader);
        setPersistentData(pd);
    }
    if (!reader.closeVersion()) {
        throw Exception(EC_InternalError, "Cannot close DataReader");
    }
}


} // namespace powerAuth
