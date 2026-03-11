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

#include <PowerAuth/ActivationService.h>
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class ActivationServiceV4 :
    public ServiceWithContext,
    public IActivationService,
    public std::enable_shared_from_this<ActivationServiceV4>
{
public:
    ActivationServiceV4(const ContextPtr& context);
    
    ProtocolVersion protocolVersion() const noexcept override;
    IServicePtr asService() override;
    RequestPtr createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data) override;
    RequestPtr confirmActivation(const InitialCredentialsPtr& credentials) override;
    std::string calculateActivationFingerprint() override;
    
    void resetState() override;
    RequestPtr fetchActivationStatus() override;
    RequestPtr removeActivation(const CredentialsPtr& credentials) override;
    
    RequestPtr changePassword(const PasswordPtr& old_password, const PasswordPtr& new_password) override;
    RequestPtr addBiometricFactor(const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek) override;
    RequestPtr removeBiometricFactor() override;
    void cleanupBiometricFactorData() override;
    
    RequestPtr fetchUserInfo() override;
    
    // IService
    void clearActivationData() override;
    
private:
    
    // Activation create
    
    /// Prepare data for create activation request.
    /// - Parameters:
    ///   - context: Context reference.
    ///   - L1_data: L1 activation data.
    ///   - L2_data: L2 activation data.
    /// - Returns: JSON representation with activation data.
    cc7::json::JsonValue prepareRequestActivationData(Context& context, cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    
    /// Process response received from activation creation endpoint.
    /// - Parameters:
    ///   - context: Context reference.
    ///   - L1_data: L1 activation data received from the server
    /// - Returns: `ActivationResult` object
    ResponseObjectPtr processResponseActivationData(Context& context, const cc7::json::JsonValue& L1_data);
    
    /// Process response received from activation confirm endpoint.
    /// - Parameters:
    ///   - context: Context reference.
    ///   - credentials: Initial credentials.
    /// - Returns: Response object. The current implementation always returns `nullptr`.
    ResponseObjectPtr processResponseActivationConfirm(Context& context, InitialCredentialsPtr credentials);
    
    // Activation fingerprint & status
    
    ResponseObjectPtr processResponseActivationStatus(Context& context, const cc7::json::JsonValue& response);
    
    ActivationStatus::CounterState trySynchronizeCounter(const ActivationStatus::BinaryData& data, const cc7::ByteRange& key_ctr_data);
    
    int calculateHashCounterDistance(cc7::ByteArray& local_ctr_data,
                                     const cc7::ByteRange& server_ctr_data_hash,
                                     const cc7::ByteRange& key_ctr_data,
                                     int max_iterations);
    
    /// Calculate human readable fingerprint from device and server's public keys.
    /// - Parameters:
    ///   - context: Context reference.
    ///   - device_public_key: Device public key.
    ///   - server_public_key: Server public key.
    /// - Returns: Human readable activation fingerprint.
    std::string calculateActivationFingerprint(Context& context,
                                               const cc7::crypto::PublicKey& device_public_key,
                                               const cc7::crypto::PublicKey& server_public_key) const;
    
    
    // Password
    
    ResponseObjectPtr processResponseChangePassword(Context& context,
                                                    SharedSecretContextPtr ss_context,
                                                    const cc7::json::JsonValue& response,
                                                    CredentialsPtr old_credentials,
                                                    CredentialsPtr new_credentials);
    
    // Biometry

    ResponseObjectPtr processResponseAddBiometricFactor(Context& context,
                                                        SharedSecretContextPtr ss_context,
                                                        const cc7::json::JsonValue& response,
                                                        const cc7::ByteRange& new_biometry_kek);
    
    /// Process response from remove biometry request.
    /// - Parameter context: Context reference.
    void doRemoveBiometricFactor(Context& context);
    
    const SessionDataPtr _session_data;
    
    std::string _activation_fingerprint;
};

} // namespace v4
} // namespace powerAuth

