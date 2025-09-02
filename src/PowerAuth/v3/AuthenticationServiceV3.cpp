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

#include "AuthenticationServiceV3.h"
#include "FunctionsV3.h"
#include "../model/Constants.h"
#include "../common/CommonFunctions.h"
#include "../request/RequestBuilder.h"
#include "../HttpHeaderHelper.h"

namespace powerAuth {
namespace v3 {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

AuthenticationServiceV3::AuthenticationServiceV3(const ContextPtr& context) :
    Service("AuthenticationServiceV3", context->getSharedMutexPtr()),
    _weak_context(context),
    _configuration(context->getConfigurationPtr()),
    _session_data(context->getSessionDataPtr()),
    _key_provider(context->getKeyProviderPtr())
{
}

IServicePtr AuthenticationServiceV3::asService()
{
    return shared_from_this();
}

HttpHeader AuthenticationServiceV3::calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                               const OnlineAuthenticationData& auth_data,
                                               const cc7::ByteRange& body)
{
    LOCK_GUARD();
    
    if (_session_data->hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Authentication header calculation is not allowed during activation registration");
    }
    
    if (_session_data->hasUpgradeData() && !auth_data.allowedInUpgrade) {
        throw Exception(EC_WrongActivationState, "Authentication header calculation is not allowed during pending protocol upgrade");
    }
    
    auto nonce = cc7::crypto::GetRandomData(v3::ONLINE_AUTH_CODE_NONCE_LENGTH);
    AuthenticationHeaderData header_data {
        Version_V3,
        _configuration->applicationKey(),
        _session_data->getActivationId(),
        credentials.factorsString(),
        nonce.base64()
    };
    auto normalized_data = common::NormalizeDataForAuthCodeCalculation(auth_data.httpMethod,
                                                                       auth_data.uriIdentifier,
                                                                       header_data.nonce,
                                                                       body,
                                                                       _configuration->applicationSecret());
    
    auto& pd = _session_data->persistentData().v3();
    auto secrets = _key_provider->unlockSecretKeys(credentials);
    auto factor_keys = prepareFactorKeys(*secrets, credentials.factors());
    auto auth_code = CalculateOnlineAuthenticationCode(factor_keys, pd.authCodeCounterData, normalized_data);
    
    _key_provider->lockSecretKeys(secrets);
    moveCounterForward(pd.authCodeCounterData, pd.authCodeCounterByte);
    
    header_data.authenticationCode = auth_code.base64();
    return HttpHeaderHelper::buildAuthenticationHeader(header_data);
}

std::string AuthenticationServiceV3::calculateOfflineAuthenticationCode(const Credentials& credentials,
                                               const OfflineAuthenticationData& auth_data,
                                               const cc7::ByteRange& data)
{
    LOCK_GUARD();
    if (auth_data.authenticationCodeLength < common::DECIMAL_AUTH_CODE_MIN_LENGTH || auth_data.authenticationCodeLength > common::DECIMAL_AUTH_CODE_MAX_LENGTH) {
        throw Exception(EC_WrongParameter, "Offline code length is out of supported range");
    }
    
    if (auth_data.offlineNonce.size() != common::OFFLINE_AUTH_CODE_NONCE_LENGTH) {
        throw Exception(EC_WrongParameter, "Offline nonce has wrong size");
    }
    
    if (_session_data->hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Offline authentication code calculation is not allowed during activation registration");
    }
    
    if (_session_data->hasUpgradeData()) {
        throw Exception(EC_WrongActivationState, "Offline authentication code calculation is not allowed during protocol upgrade");
    }
    
    auto normalized_data = common::NormalizeDataForAuthCodeCalculation("POST",
                                                                       auth_data.uriIdentifier,
                                                                       auth_data.offlineNonce,
                                                                       data,
                                                                       common::PA_OFFLINE_APP_SECRET);
    
    auto& pd = _session_data->persistentData().v3();
    auto secrets = _key_provider->unlockSecretKeys(credentials);
    
    auto factor_keys = prepareFactorKeys(*secrets, credentials.factors());
    auto auth_code = CalculateOfflineAuthenticationCode(factor_keys, pd.authCodeCounterData, normalized_data, auth_data.authenticationCodeLength);
    
    _key_provider->lockSecretKeys(secrets);
    moveCounterForward(pd.authCodeCounterData, pd.authCodeCounterByte);
    
    return auth_code;
}

RequestPtr AuthenticationServiceV3::verifyCredentials(const CredentialsPtr& credentials, const cc7::json::JsonValue& body)
{
    if (auto context = _weak_context.lock()) {
        return RequestBuilder(*context, v3::Endpoint_SignatureValidate)
            .withJson(body)
            .withAuthentication(credentials)
            .build();
    }
    throw Exception(EC_MissingActivation, "Session object is destroyed");
}

std::vector<cc7::ByteRange> AuthenticationServiceV3::prepareFactorKeys(ISecretKeys &secrets, AuthFactors factors)
{
    // Prepare array with factor keys
    std::vector<cc7::ByteRange> factor_keys;
    factor_keys.push_back(secrets.keyAuthenticationCodePossession());
    switch (factors) {
        case AuthFactors::POSSESSION:
            break;
        case AuthFactors::POSSESSION_KNOWLEDGE:
            factor_keys.push_back(secrets.keyAuthenticationCodeKnowledge());
            break;
        case AuthFactors::POSSESSION_BIOMETRY:
            factor_keys.push_back(secrets.keyAuthenticationCodeBiometry());
            break;
    }
    return factor_keys;
}

void AuthenticationServiceV3::moveCounterForward(cc7::ByteArray& hash_counter, cc7::byte& byte_counter)
{
    hash_counter = ReduceSharedSecret(algorithms().v3.sha256().digest(hash_counter));
    byte_counter += 1;
}

} // namespace v3
} // namespace powerAuth
