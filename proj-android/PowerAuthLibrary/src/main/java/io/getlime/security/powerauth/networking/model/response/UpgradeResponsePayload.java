/*
 * Copyright 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.networking.model.response;

/**
 * Response object for upgrade payload.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class UpgradeResponsePayload {

    private String ctrData;

    /**
     * Get counter data.
     * @return Counter data.
     */
    public String getCtrData() {
        return ctrData;
    }

    /**
     * Set counter data.
     * @param ctrData Counter data.
     */
    public void setCtrData(String ctrData) {
        this.ctrData = ctrData;
    }
}