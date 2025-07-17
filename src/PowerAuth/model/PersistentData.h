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

#include <PowerAuth/Types.h>

#include <cc7/utils/DataReader.h>
#include <cc7/utils/DataWriter.h>
#include <cc7/BaseObject.h>

#include "Constants.h"

namespace powerAuth {

/// The `PersistentData` contains long term data related to PowerAuth activation.
class PersistentData
{
public:
    
    /// V3 persistent data.
    struct V3
    {
        /// V3: Data for hash-based counter for authorization code calculations
        cc7::ByteArray  authCodeCounterData;
        /// V3.1: Least significant byte from the signature counter
        cc7::byte       authCodeCounterByte;
        /// ActivationId, that's our identity known on the server
        std::string     activationId;
        /// Number of iterations for PBKDF2
        cc7::U32        passwordIterations;
        /// Salt value for PBKDF2
        cc7::ByteArray  passwordSalt;
        
        /// Actual signature keys. Each key in the structure is encrypted
        cc7::ByteArray  cPossessionKey;
        cc7::ByteArray  cKnowledgeKey;
        cc7::ByteArray  cBiometryKey;
        cc7::ByteArray  cTransportKey;
        
        /// Server's public key
        cc7::ByteArray  serverPublicKey;
        /// Device's public key
        cc7::ByteArray  devicePublicKey;
        /// Encrypted device's private key.
        cc7::ByteArray  cDevicePrivateKey;

        struct _Flags {
            /// True if the session is waiting for vault key unlock.
            /// The flag is deprecated sice protocol V3, and should not be used.
            cc7::U32    waitingForVaultUnlock   : 1;
            /// True if activation was established with additional
            /// external key.
            cc7::U32    usesExternalKey         : 1;
             /// Bits reserved for current pending protocol upgrade
            cc7::U32    pendingUpgradeVersion   : 8;
            /// True if `signatureCounterByte` is valid and can be used for calculations.
            cc7::U32    hasAuthCodeCounterByte : 1;
        };
        union {
            _Flags      flags;
            cc7::U32    flagsU32;
        };
    };
    
    struct V4
    {
        /// SharedSecret::Algorithm used for shared secret calculation.
        cc7::byte       algorithmId;
        /// ActivationId, that's our identity known on the server
        std::string     activationId;

        /// V4: Least significant byte from the signature counter
        cc7::byte       authCodeCounterByte;
        /// V4: Data for hash-based counter for authorization code calculations
        cc7::ByteArray  authCodeCounterData;
        /// Salt value for PowerAuthPassKDF
        cc7::ByteArray  passwordSalt;

        /// Encrypted possession factor key.
        cc7::ByteArray  cPossessionKey;
        /// Encrypted knowledge factor key.
        cc7::ByteArray  cKnowledgeKey;
        /// Encrypted biometry factor key.
        cc7::ByteArray  cBiometryKey;
        
        /// Encrypted `KDK_UTILITY`.
        cc7::ByteArray  cKdkUtility;
        /// Encrypted `KDK_ENCRYPTION`
        cc7::ByteArray  cKdkEncryption;
                
        /// Device's public key
        cc7::ByteArray  cDevicePublicKey;
        /// Server's public key
        cc7::ByteArray  cServerPublicKey;
        /// Encrypted device's private key.
        cc7::ByteArray  cDevicePrivateKey;
    };
    
    /// Returns activation identifier.
    const std::string& getActivationId() const noexcept;
    
    /// Returns information whether biometric factor key is set.
    bool hasBiometricFactorKey() const noexcept;
    
    // Versioned data
    ProtocolVersion getProtocolVersion() const noexcept;
    
    /// Return information whether the structure has been modified.
    bool isModified() const noexcept;
    
    V3& v3();
    const V3& v3() const;
    
    V4& v4();
    const V4& v4() const;
    
    // Object construction
    
    /// Create persistent data structure with V4 data.
    ///
    /// - Parameter v4: Unique pointer with V4 data.
    /// - Returns: Persistent data pointer with V4 data.
    static std::unique_ptr<PersistentData> create(std::unique_ptr<V4>& v4);

    /// Create persistent data structure with V3 data.
    ///
    /// Note that this method should be used only for testing purposes.
    ///
    /// - Parameter v3: Unique pointer with V3 data.
    /// - Returns: Persistent data pointer with V3 data.
    static std::unique_ptr<PersistentData> create(std::unique_ptr<V3>& v3);

    /// Serialize content of persistent data object into writer and clear modified flag.
    ///  - Parameter writer: DataWriter object.
    void serialize(cc7::utils::DataWriter& writer);
    
    /// Create PersistentData instance from previously serialized data.
    static std::unique_ptr<PersistentData> deserialize(cc7::utils::DataReader& reader);
    
private:
    
    /// Data version
    const ProtocolVersion _version;
    /// Pointer to V3 data
    const std::unique_ptr<V3> _v3;
    /// Pointer to V4 data
    const std::unique_ptr<V4> _v4;
    /// Content of data structure is modified
    bool _modified;

    /// Construct a persistent data object with V3 data.
    /// - Parameters:
    ///   - v3_data: V3 data
    ///   - modified: If true, this is unsaved data
    PersistentData(std::unique_ptr<V3>& v3_data, bool modified);
    
    /// Construct a persistent data object with V4 data.
    /// - Parameters:
    ///   - v4_data: V4 data
    ///   - modified: If true, this is unsaved data
    PersistentData(std::unique_ptr<V4>& v4_data, bool modified);
    
    /// Serialize V3 structure into DataWriter.
    /// - Parameters:
    ///   - writer: DataWriter object
    ///   - v3: V3 structure
    void serializeV3(cc7::utils::DataWriter& writer, const V3& v3) const noexcept;
    
    /// Serialize V4 structure into DataWriter.
    /// - Parameters:
    ///   - writer: DataWriter object
    ///   - v4: V4 structure
    void serializeV4(cc7::utils::DataWriter& writer, const V4& v4) const noexcept;
    
    /// Deserialize V3 structure from DataReader.
    /// - Parameters:
    ///   - reader: DataReader object
    ///   - v3: output V3 structure
    /// - Returns: true in case of success.
    static bool deserializeV3(cc7::utils::DataReader& reader, V3& v3);
    
    /// Deserialize V4 structure from DataReader.
    /// - Parameters:
    ///   - reader: DataReader object
    ///   - v4: output V4 structure
    /// - Returns: true in case of success.
    static bool deserializeV4(cc7::utils::DataReader& reader, V4& v4);
    
    /// Validate content of V3 structure.
    /// - Parameter v3: V3 structure
    /// - Returns: true in case of success.
    static bool validateV3(const V3& v3);
    
    /// Validate content of V4 structure.
    /// - Parameter v4: V4 structure
    /// - Returns: true in case of success.
    static bool validateV4(const V4& v4);
};

typedef std::unique_ptr<PersistentData> PersistentDataPtr;

} // namespace powerAuth
