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

package io.getlime.security.powerauth.networking.endpoints;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;


/**
 * Created by miroslavmichalec on 25/10/2016.
 */

public class PA2ActivationStatusEndpoint implements IEndpointDefinition<ActivationStatusResponse> {

    private String baseUrl;

    /**
     * Create a new activation status endpoint with given PowerAuth 2.0 API base URL.
     * @param baseUrl Base URL of the PA2.0 API endpoints.
     */
    public PA2ActivationStatusEndpoint(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public static final String ACTIVATION_STATUS = "/pa/activation/status";

    @Override
    public String getEndpoint() {
        return baseUrl + ACTIVATION_STATUS;
    }

    @Override
    public TypeToken<ActivationStatusResponse> getResponseType() {
        return TypeToken.get(ActivationStatusResponse.class);
    }
}
