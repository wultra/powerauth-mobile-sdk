/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.model;

import android.util.Base64;

import androidx.annotation.NonNull;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Arrays;

public class OfflineSignaturePayload {

    private String nonce;
    @SerializedName("offlineData")
    private String data;

    @Expose(serialize = false)
    private String[] dataComponents;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
        this.dataComponents = null;
    }

    @NonNull
    public String[] getParsedComponents() {
        if (dataComponents == null) {
            if (data == null) {
                throw new IllegalStateException("No offline data received");
            }
            String[] components = data.split("\n");
            int count = components.length;
            if (components.length <= 2) {
                throw new IllegalStateException("Wrong offline data received");
            }
            String nonce = components[count - 2];
            String signS = components[count - 1];
            String key = signS.substring(0, 1);
            String sign = signS.substring(1);
            String data = String.join("\n", Arrays.copyOfRange(components, 0, count - 2));
            dataComponents = new String[] { data, nonce, key, sign };
        }
        return dataComponents;
    }
    public String getParsedData() {
        return getParsedComponents()[0];
    }

    public byte[] getParsedDataBytes() {
        return Base64.decode(getParsedData(), Base64.NO_WRAP);
    }

    public String getParsedNonce() {
        return getParsedComponents()[1];
    }

    public String getParsedSigningKey() {
        return getParsedComponents()[2];
    }

    public String getParsedSignature() {
        return getParsedComponents()[3];
    }

    public String getParsedSignedData() {
        String[] components = getParsedComponents();
        return String.join("\n", Arrays.copyOfRange(components, 0, components.length - 1));
    }
}
