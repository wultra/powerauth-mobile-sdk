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

import java.util.Date;

/**
 * Response object for a system status call.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ServiceStatusResponse {

    private String applicationName;
    private String applicationDisplayName;
    private String applicationEnvironment;
    private String version;
    private Date buildTime;
    private Date timestamp;

    /**
     * Get the application name.
     * @return Application name.
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Set the application name.
     * @param applicationName Application name.
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Get the application display name.
     * @return Application display name.
     */
    public String getApplicationDisplayName() {
        return applicationDisplayName;
    }

    /**
     * Set the application display name.
     * @param applicationDisplayName Application display name.
     */
    public void setApplicationDisplayName(String applicationDisplayName) {
        this.applicationDisplayName = applicationDisplayName;
    }

    /**
     * Get application environment name.
     * @return Environment name.
     */
    public String getApplicationEnvironment() {
        return applicationEnvironment;
    }

    /**
     * Set application environment name.
     * @param applicationEnvironment Environment name.
     */
    public void setApplicationEnvironment(String applicationEnvironment) {
        this.applicationEnvironment = applicationEnvironment;
    }

    /**
     * Get version.
     * @return version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set version.
     * @param version Version.
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Get build time.
     * @return Build time.
     */
    public Date getBuildTime() {
        return buildTime;
    }

    /**
     * Set build time.
     * @param buildTime Build time.
     */
    public void setBuildTime(Date buildTime) {
        this.buildTime = buildTime;
    }

    /**
     * Get current timestamp.
     * @return Timestamp.
     */
    public Date getTimestamp() {
        return timestamp;
    }

    /**
     * Set current timestamp.
     * @param timestamp Timestamp.
     */
    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }
}
