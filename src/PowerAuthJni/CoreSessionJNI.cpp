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

#include "NativeHelper.h"
#include "SecureDataJNI.h"
#include <PowerAuth/Session.h>
#include <cc7/jni/JniJson.h>

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH          "io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE       io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS          CoreSession
#define CC7_JNI_CPP_CLASS           Session
#include <cc7/jni/JniModule.inl>

using namespace powerAuth;
using namespace powerAuth::jni;
using namespace cc7::json;
using namespace cc7::jni;

CC7_JNI_MODULE_CLASS_BEGIN()

#define THIS_OBJ()  jni.fromJava<CC7_JNI_CPP_CLASS>(NH_SPECS().coreSession.native, thiz)

// Construction

CC7_JNI_STATIC_METHOD_PARAMS(jobject, createSession, jobject configuration)
{
    NH_TRY
    {
        jni.requireParameter(configuration, "configuration");
        auto& specs = NH_SPECS();
        auto cpp_config = jni.fromJava<Configuration>(specs.coreConfig, configuration);
        // Build C++ Session instance.
        auto cpp_session = Session::createInstance(cpp_config);
        // Register C++ object
        auto session_handle = jni.toHandle(cpp_session);
        // create java wrapper for time service
        auto time_service = jni.toJava(specs.coreTimeService, cpp_session->getTimeService());
        // Build final CoreSession java object
        return jni.createObject(specs.coreSession.init, session_handle, configuration, time_service);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(void, resetSession)
{
    NH_TRY
    {
        THIS_OBJ()->resetState();
    }
    NH_CATCH_RT_ONLY()
}

// Getters

CC7_JNI_METHOD(jstring, getApplicationKey)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->getConfiguration()->applicationKey());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jint, getCurrentAlgorithm)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreAlgorithm, THIS_OBJ()->getPowerAuthSpec()->algorithm());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jint, getProtocolVersion)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreProtocolVersion, THIS_OBJ()->getProtocolVersion());
    }
    NH_CATCH_RT_ONLY(0)
}

CC7_JNI_METHOD(jboolean, canCreateActivation)
{
    NH_TRY
    {
        return THIS_OBJ()->canCreateActivation();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasPendingCreateActivation)
{
    NH_TRY
    {
        return THIS_OBJ()->hasPendingCreateActivation();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasValidActivationData)
{
    NH_TRY
    {
        return THIS_OBJ()->hasValidActivationData();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasProtocolUpgradeAvailable)
{
    NH_TRY
    {
        return THIS_OBJ()->hasProtocolUpgradeAvailable();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD(jboolean, hasPendingProtocolUpgrade)
{
    NH_TRY
    {
        return THIS_OBJ()->hasPendingProtocolUpgrade();
    }
    NH_CATCH_RT_ONLY(false)
}

// Serialization

CC7_JNI_METHOD(jbyteArray, getSerializedState)
{
    NH_TRY
    {
        return jni.toJava(THIS_OBJ()->saveState());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(void, deserializeState, jbyteArray serializedState)
{
    NH_TRY
    {
        THIS_OBJ()->loadState(jni.fromJava(serializedState));
    }
    NH_CATCH()
}

CC7_JNI_METHOD(jboolean, isModifiedState)
{
    NH_TRY
    {
        return THIS_OBJ()->isModifiedState();
    }
    NH_CATCH_RT_ONLY(false)
}

// Activation

CC7_JNI_METHOD(jstring, getActivationIdentifier)
{
    NH_TRY
    {
        return jni.toJavaNullable(THIS_OBJ()->activationId());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD(jstring, getActivationFingerprint)
{
    NH_TRY
    {
        return jni.toJavaNullable(THIS_OBJ()->activationFingerprint());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, createActivation, jobject L1Data, jobject L2Data)
{
    NH_TRY
    {
        jni.requireParameter(L1Data, "L1Data");
        jni.requireParameter(L2Data, "L2Data");
        auto L1 = JsonValueFromJava(jni, L1Data);
        auto L2 = JsonValueFromJava(jni, L2Data);
        auto request = THIS_OBJ()->createActivation(L1, L2);
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto result = std::dynamic_pointer_cast<ActivationResult>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No ActivationResult object created");
            }
            return jni.createObject(specs.respActivationResult.methods.init,
                                    jni.toJava(result->activationFingerprint()),
                                    JsonValueToJava(jni, result->customAttributes()),
                                    JsonValueToJava(jni, result->userInfo()));
        });
    }
    NH_CATCH(nullptr)
}

/// Build Java `CoreActivationStatus` from C++ ActivationStatus object.
static jobject BuildActivationStatus(JNI& jni, const ClassSpecs& specs, const ActivationStatusPtr& status)
{
    // constructor (int state,
    //              int failCount,
    //              int maxFailCount,
    //              int remainingAttempts,
    //              boolean isProtocolUpgradeAvailable,
    //              boolean isCounterSynchronizationRecommended,
    //              boolean isSessionSerializationNeeded,
    //              Map<String, Object> customObject)
    return jni.createObject(specs.respActivationStatus.methods.init,
                            jni.toJava(specs.coreActivationState, status->activationState()),
                            (jint) status->failCount(),
                            (jint) status->maxFailCount(),
                            (jint) status->remainingAttempts(),
                            status->isProtocolUpgradeAvailable(),
                            status->isCounterSynchronizationRecommended(),
                            status->isSessionStateSerializationRecommended(),
                            JsonValueToJava(jni, status->customObject()));
}

CC7_JNI_METHOD(jobject, fetchActivationStatus)
{
    NH_TRY
    {
        auto task = THIS_OBJ()->fetchActivationStatus();
        return BuildCoreTask(jni, task, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto result = std::dynamic_pointer_cast<ActivationStatus>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No ActivationStatus object created");
            }
            return BuildActivationStatus(jni, specs, result);
        });
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jobject, getLastActivationStatus)
{
    NH_TRY
    {
        auto status = THIS_OBJ()->lastActivationStatus();
        return status ? BuildActivationStatus(jni, NH_SPECS(), status) : nullptr;
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, confirmActivation, jobject password, jobject biometryKek)
{
    NH_TRY
    {
        jni.requireParameter(password, "password");
        auto& specs = NH_SPECS();
        auto cpp_password = jni.fromJava<Password>(specs.password, password);
        auto cpp_biometry = CopyFromSecureData(jni, biometryKek);
        auto credentials = InitialCredentials::credentials(cpp_password->passwordData(), cpp_biometry);
        auto request = THIS_OBJ()->confirmActivation(credentials);
        if (!request) {
            // This is valid for V3 activations
            return nullptr;
        }
        return BuildCoreRequest(jni, request);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, removeActivation, jobject credentials)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        auto cpp_credentials = jni.fromJava<Credentials>(NH_SPECS().coreCredentials, credentials);
        auto request = THIS_OBJ()->removeActivation(cpp_credentials);
        return BuildCoreRequest(jni, request);
    }
    NH_CATCH(nullptr)
}

// Factor keys management

CC7_JNI_METHOD(jboolean, hasBiometryFactor)
{
    NH_TRY
    {
        return THIS_OBJ()->hasBiometricFactor();
    }
    NH_CATCH_RT_ONLY(false)
}

CC7_JNI_METHOD_PARAMS(jobject, verifyPassword, jobject password)
{
    NH_TRY
    {
        jni.requireParameter(password, "password");
        auto cpp_password = jni.fromJava<Password>(NH_SPECS().password, password);
        auto request = THIS_OBJ()->verifyPassword(cpp_password);
        return BuildCoreRequest(jni, request);
    }
    NH_CATCH(nullptr)
}

// Authentication

CC7_JNI_METHOD_PARAMS(jobject, calculateOnlineAuthenticationHeader, jobject credentials, jstring uriIdentifier, jstring httpMethod, jbyteArray requestBody)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        jni.requireParameter(uriIdentifier, "uriIdentifier");
        jni.requireParameter(httpMethod, "httpMethod");
        auto& specs = NH_SPECS();
        auto result = THIS_OBJ()->calculateOnlineAuthenticationHeader(
                *jni.fromJava<Credentials>(specs.coreCredentials, credentials),
                jni.fromJava(uriIdentifier),
                jni.fromJava(httpMethod),
                jni.fromJava(requestBody));
        return jni.createObject(specs.coreHttpHeader.methods.init,
                                jni.toJava(result.headerName),
                                jni.toJava(result.headerValue));
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, calculateOfflineAuthenticationCode, jobject credentials, jstring uriIdentifier, jstring offlineNonce, jint codeLength, jbyteArray data)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        jni.requireParameter(uriIdentifier, "uriIdentifier");
        jni.requireParameter(offlineNonce, "offlineNonce");
        auto& specs = NH_SPECS();
        auto result = THIS_OBJ()->calculateOfflineAuthenticationCode(
                *jni.fromJava<Credentials>(specs.coreCredentials, credentials),
                jni.fromJava(uriIdentifier),
                jni.fromJava(offlineNonce),
                jni.fromJava(data),
                (size_t)codeLength);
        return jni.toJava(result);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jbyteArray, normalizeGetRequestParameters, jobject parameters)
{
    NH_TRY
    {
        if (parameters == nullptr) {
            return nullptr;
        }
        // Convert Map<String, String> into std::map<std::string, std::string>
        std::map<std::string, std::string> map;
        auto& specs = jni.commonSpecs();
        auto wrapped = jni.fromJava(parameters);
        auto entry_set = jni.fromJava(wrapped.callObject(specs.specMap.methods.entrySet));
        auto iterator = jni.fromJava(entry_set.callObject(specs.specSet.methods.iterator));
        while (iterator.callBoolean(specs.specIterator.methods.hasNext)) {
            auto entry = jni.fromJava(iterator.callObject(specs.specIterator.methods.next));
            auto key = entry.callString(specs.specMapEntry.methods.getKey);
            auto value = entry.callString(specs.specMapEntry.methods.getValue);
            map[key] = value;
            // cleanup
            jni.releaseLocal(entry);
        }

        auto result = THIS_OBJ()->getAuthenticationService()->normalizeGetRequestParameters(map);
        return jni.toJava(result);
    }
    NH_CATCH(nullptr)
}

// Tokens

CC7_JNI_METHOD_PARAMS(jobject, calculateTokenHeader, jstring tokenIdentifier, jbyteArray tokenSecret)
{
    NH_TRY
    {
        jni.requireParameter(tokenIdentifier, "tokenIdentifier");
        jni.requireParameter(tokenSecret, "tokenSecret");
        auto result = THIS_OBJ()->calculateTokenHeader(jni.fromJava(tokenIdentifier), jni.fromJava(tokenSecret));
        return jni.createObject(NH_SPECS().coreHttpHeader.methods.init,
                                jni.toJava(result.headerName),
                                jni.toJava(result.headerValue));
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, createAccessToken, jobject credentials)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        auto& specs = NH_SPECS();
        auto request = THIS_OBJ()->createAccessToken(jni.fromJava<Credentials>(specs.coreCredentials, credentials));
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto result = std::dynamic_pointer_cast<GetAccessTokenResponse>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No GetAccessTokenResponse object created");
            }
            return jni.createObject(specs.respTokenData.methods.init,
                                    jni.toJava(result->getIdentifier()),
                                    jni.toJava(result->getSecret()));
        });
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, removeAccessToken, jstring tokenIdentifier)
{
    NH_TRY
    {
        jni.requireParameter(tokenIdentifier, "tokenIdentifier");
        auto request = THIS_OBJ()->removeAccessToken(jni.fromJava(tokenIdentifier));
        return BuildCoreRequest(jni, request);
    }
    NH_CATCH(nullptr)
}

// Digital signatures

/// Enumeration identical to `io.getlime.security.powerauth.core.CoreDevicePublicKeyFormat`.
/// We don't need to expose it as a public interface.
enum class CoreDevicePublicKeyFormat
{
    SPKI = 0,
    RAW = 1
};

CC7_JNI_METHOD_PARAMS(jobjectArray, exportDevicePublicKeys, jint format)
{
    NH_TRY
    {
        auto& specs = NH_SPECS();
        auto key_format = jni.fromJava<CoreDevicePublicKeyFormat>(specs.coreDevicePublicKeyFormat, format);
        auto keys = THIS_OBJ()->exportDevicePublicKeys(key_format == CoreDevicePublicKeyFormat::SPKI ? cc7::crypto::KEY_FORMAT_SPKI : cc7::crypto::KEY_FORMAT_RAW);
        auto result = jni.createObjectArray(specs.coreDevicePublicKeyData.classRef, keys.size());
        for (jsize index = 0; index < keys.size(); ++index) {
            const auto& key = keys[index];
            auto key_data = jni.createObject(specs.coreDevicePublicKeyData.methods.init,
                                             jni.toJava(specs.coreSignatureKeyType, key.keyType),
                                             jni.toJava(key.keyAlgorithm),
                                             jni.toJava(key.keyData));
            result.setObject(index, key_data);
            key_data.releaseLocal();
        }
        return result;
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(void, verifySignature, jbyteArray signature, jbyteArray data, jint keyId)
{
    NH_TRY
    {
        jni.requireParameter(signature, "signature");
        THIS_OBJ()->verifySignature(jni.fromJava(data),
                                    jni.fromJava(signature),
                                    jni.fromJava<SignatureKeyId>(NH_SPECS().coreSignatureKeyId, keyId));
    }
    NH_CATCH()
}

CC7_JNI_METHOD_PARAMS(jobject, signData, jbyteArray data, jobject credentials, jint keyId)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        auto& specs = NH_SPECS();
        auto request = THIS_OBJ()->signData(jni.fromJava<Credentials>(specs.coreCredentials, credentials),
                                            jni.fromJava(data),
                                            jni.fromJava<SignatureKeyId>(specs.coreSignatureKeyId, keyId));
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto result = std::dynamic_pointer_cast<DataResponse>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No DataResponse object created");
            }
            return jni.toJava(result->data());
        });
    }
    NH_CATCH(nullptr)
}

// JWS

CC7_JNI_METHOD_PARAMS(void, jwsVerifySignature, jstring signature, jboolean compactForm, jboolean strict, jint keyId)
{
    NH_TRY
    {
        jni.requireParameter(signature, "signature");
        THIS_OBJ()->jwsVerifySignature(jni.fromJava(signature),
                                       jni.fromJava<SignatureKeyId>(NH_SPECS().coreSignatureKeyId, keyId),
                                       compactForm,
                                       strict);
    }
    NH_CATCH()
}

CC7_JNI_METHOD_PARAMS(jobject, jwsSignData, jbyteArray data, jstring dataType, jboolean compactForm, jobject credentials, jint keyId)
{
    NH_TRY
    {
        jni.requireParameter(credentials, "credentials");
        auto& specs = NH_SPECS();
        auto request = THIS_OBJ()->jwsSignData(jni.fromJava<Credentials>(specs.coreCredentials, credentials),
                                               jni.fromJava(data),
                                               jni.fromJava(dataType),
                                               jni.fromJava<SignatureKeyId>(specs.coreSignatureKeyId, keyId),
                                               compactForm);
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            auto result = std::dynamic_pointer_cast<StringResponse>(response);
            if (!result) {
                throw Exception(EC_InternalError, "No StringResponse object created");
            }
            return jni.toJava(result->string());
        });
    }
    NH_CATCH(nullptr)
}

// Services

CC7_JNI_METHOD(jobject, getEncryptorFactory)
{
    NH_TRY
    {
        return jni.toJava(NH_SPECS().coreEncryptorFactory, THIS_OBJ()->getEncryptorFactory());
    }
    NH_CATCH_RT_ONLY(nullptr)
}

// Utilities

CC7_JNI_METHOD(jobject, generateFactorKek)
{
    NH_TRY
    {
        return CopyToSecureData(jni, THIS_OBJ()->generateFactorKek());
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD_PARAMS(jobject, generateFactorKekFromData, jobject data)
{
    NH_TRY
    {
        jni.requireParameter(data, "data");
        auto input_data = CopyFromSecureData(jni, data);
        auto kek = THIS_OBJ()->generateFactorKekFromData(input_data);
        return CopyToSecureData(jni, kek);
    }
    NH_CATCH(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jobject, generateFactorKekForProtocolVersion, jint protocolVersion)
{
    NH_TRY
    {
        auto version = jni.fromJava<ProtocolVersion>(NH_SPECS().coreProtocolVersion, protocolVersion);
        return CopyToSecureData(jni, Session::generateFactorKekForProtocol(version));
    }
    NH_CATCH(nullptr)
}

CC7_JNI_STATIC_METHOD_PARAMS(jstring, maxSupportedHttpProtocolVersion, jint protocolVersion)
{
    NH_TRY
    {
        auto version = jni.fromJava<ProtocolVersion>(NH_SPECS().coreProtocolVersion, protocolVersion);
        return jni.toJava(ProtocolVersion_GetHttpHeaderVersion(version));
    }
    NH_CATCH_RT_ONLY(nullptr)
}

// User Info

CC7_JNI_METHOD(jobject, fetchUserInfo)
{
    NH_TRY
    {
        auto request = THIS_OBJ()->fetchUserInfo();
        return BuildCoreRequest(jni, request, [](JNI& jni, const ClassSpecs& specs, const ResponseObjectPtr& response, const JsonValue& response_json) -> jobject {
            return JsonValueToJava(jni, response_json);
        });
    }
    NH_CATCH(nullptr)
}

CC7_JNI_METHOD(jobject, getLastUserInfo)
{
    NH_TRY
    {
        auto userInfo = THIS_OBJ()->lastUserInfo();
        return cc7::jni::JsonValueToJava(jni, userInfo);
    }
    NH_CATCH_RT_ONLY(nullptr)
}

CC7_JNI_MODULE_CLASS_END()
