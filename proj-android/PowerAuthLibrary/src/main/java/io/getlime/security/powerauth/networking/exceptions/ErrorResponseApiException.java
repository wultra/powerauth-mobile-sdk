/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.exceptions;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import io.getlime.core.rest.model.base.entity.Error;

/**
 * Signals that a REST connection failed with a known error. You can check
 * the reason of failure in the attached ErrorModel object.
 */
public class ErrorResponseApiException extends FailedApiException {

    /**
     * Error response received from the server
     */
    private Error errorResponse;

    /**
     * Constructs an exception with {@link Error} model object, response code and response body.
     *
     * @param errorResponse error received from server
     * @param responseCode HTTP response code
     * @param responseBody HTTP response body, may be null if it's not available.
     * @param responseJson {@link JsonObject} with JSON root, received from the server. May be null if response
     *                     is not in JSON format.
     */
    public ErrorResponseApiException(Error errorResponse, int responseCode, String responseBody, JsonObject responseJson) {
        super(responseCode, responseBody, responseJson);
        this.errorResponse = errorResponse;
    }

    /**
     * @return {@link Error} model object with failure reason
     */
    public Error getErrorResponse() {
        return errorResponse;
    }


    /**
     * @return Index of valid PUK in case that recovery activation did fail and
     *         there's still some recovery PUK available. Returns -1 if the information is not
     *         available in the error response.
     */
    public int getCurrentRecoveryPukIndex() {
        final JsonObject errorResponse = getResponseObjectFromResponseJson();
        if (errorResponse != null) {
            final JsonElement currentRecoveryPukIndex = errorResponse.get("currentRecoveryPukIndex");
            if (currentRecoveryPukIndex != null && currentRecoveryPukIndex.isJsonPrimitive()) {
                final JsonPrimitive value = currentRecoveryPukIndex.getAsJsonPrimitive();
                if (value.isNumber()) {
                    return value.getAsInt();
                }
            }
        }
        return -1;
    }
}
