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

#include "AuthenticationServiceV4.h"
#include "FunctionsV4.h"
#include "../model/Constants.h"
#include "../common/CommonFunctions.h"
#include "../request/RequestBuilder.h"
#include "../HttpHeaderHelper.h"


using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

AuthenticationServiceV4::AuthenticationServiceV4(const ContextPtr& context) :
    Service("AuthenticationServiceV4", context->getSharedMutexPtr()),
    _weak_context(context),
    _configuration(context->getConfigurationPtr()),
    _session_data(context->getSessionDataPtr()),
    _key_provider(context->getKeyProviderPtr())
{
}

IServicePtr AuthenticationServiceV4::asService()
{
    return shared_from_this();
}

HttpHeader AuthenticationServiceV4::calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                                                        const OnlineAuthenticationData& auth_data, const
                                                                        cc7::ByteRange& body)
{
    LOCK_GUARD();
    bool is_pending_registration = _session_data->hasRegistrationData();
    if (is_pending_registration && !auth_data.allowedInPendingRegistration) {
        throw Exception(EC_WrongActivationState, "Authentication header calculation is not allowed during activation registration");
    }
    if (_session_data->hasUpgradeData() && !auth_data.allowedInUpgrade) {
        throw Exception(EC_WrongActivationState, "Authentication header calculation is not allowed during pending protocol upgrade");
    }
    auto nonce = GetRandomData(v4::ONLINE_AUTH_CODE_NONCE_LENGTH);
    AuthorizationHeaderData header_data {
        Version_V4,
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
    auto factors = credentials.factors();
    auto& hash_counter = is_pending_registration
                        ? _session_data->registrationData().v4().authCodeCounterData
                        : _session_data->persistentData().v4().authCodeCounterData;
    auto& byte_counter = is_pending_registration
                        ? _session_data->registrationData().v4().authCodeCounterByte
                        : _session_data->persistentData().v4().authCodeCounterByte;
    // unlock secret keys
    auto secrets = is_pending_registration
                        ? _key_provider->unlockSecretKeysForFactors(factors)    // If registration is pending, then we don't care about actual credentials
                        : _key_provider->unlockSecretKeys(credentials);         // unlock with credentials
    auto factor_keys = prepareFactorKeys(*secrets, factors);
    auto auth_code = CalculateOnlineAuthorizationCode(factor_keys, hash_counter, normalized_data);
    // lock secret keys
    _key_provider->lockSecretKeys(secrets);
    moveCounterForward(hash_counter, byte_counter);
    
    // move counter forward and return result
    header_data.authenticationCode = auth_code.base64();
    return HttpHeaderHelper::buildAuthorizationHeader(header_data);
}

std::string AuthenticationServiceV4::calculateOfflineAuthenticationCode(const Credentials& credentials,
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
    auto& pd = _session_data->persistentData().v4();
    // unlock secret keys
    auto secrets = _key_provider->unlockSecretKeys(credentials);
    //
    auto factor_keys = prepareFactorKeys(*secrets, credentials.factors());
    auto result = CalculateOfflineAuthorizationCode(factor_keys, pd.authCodeCounterData, normalized_data, auth_data.authenticationCodeLength);
    // lock secret keys
    _key_provider->lockSecretKeys(secrets);
    // move counter forward and return result
    moveCounterForward(pd.authCodeCounterData, pd.authCodeCounterByte);
    return result;
}

RequestPtr AuthenticationServiceV4::verifyCredentials(const CredentialsPtr& credentials, const cc7::json::JsonValue& body)
{
    if (auto context = _weak_context.lock()) {
        return RequestBuilder(*context, v4::Endpoint_ValidateCredentials)
            .withJson(body)
            .withAuthentication(credentials)
            .build();
    }
    throw Exception(EC_MissingActivation, "Session object is destroyed");
}

std::vector<ByteRange> AuthenticationServiceV4::prepareFactorKeys(ISecretKeys &secrets, AuthFactors factors)
{
    // Prepare array with factor keys
    std::vector<ByteRange> factor_keys;
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

void AuthenticationServiceV4::moveCounterForward(cc7::ByteArray& hash_counter, cc7::byte& byte_counter)
{
    hash_counter = algorithms().v4.sha3_256().digest(hash_counter);
    byte_counter += 1;
}

} // namespace v4
} // namespace powerAuth
