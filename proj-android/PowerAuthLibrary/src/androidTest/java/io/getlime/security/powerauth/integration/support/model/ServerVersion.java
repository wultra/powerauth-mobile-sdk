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

import androidx.annotation.NonNull;

/**
 * The {@link ServerVersion} enumeration defines PowerAuth Server versions.
 */
public enum ServerVersion {

    /**
     * PowerAuth Server 1.0.0 (2020.11 release)
     */
    V1_0_0("1.0", 1000000, ProtocolVersion.V3_1),
    V1_1_0("1.1", 1001000, ProtocolVersion.V3_1),
    V1_2_0("1.2", 1002000, ProtocolVersion.V3_1),
    V1_2_5("1.2.5", 1002005, ProtocolVersion.V3_1),
    V1_3_0("1.3", 1003000, ProtocolVersion.V3_1),
    V1_4_0("1.4", 1004000, ProtocolVersion.V3_1),
    V1_5_0("1.5", 1005000, ProtocolVersion.V3_1),

    ;

    /**
     * Contains constant for the latest PowerAuth Server version.
     */
    public static final ServerVersion LATEST = V1_5_0;

    /**
     * Server version represented as string.
     */
    public final @NonNull String version;

    /**
     * Numeric representation of server version, allows simple version comparison. Use following scheme to
     * define such value: {@code 1_000_000 * MAJOR + 1_000 * MINOR + PATCH}
     */
    public final int numericVersion;

    /**
     * Maximum protocol version supported on the server.
     */
    public final ProtocolVersion maxProtocolVersion;

    ServerVersion(@NonNull String version, int numericVersion, ProtocolVersion maxProtocolVersion) {
        this.version = version;
        this.numericVersion = numericVersion;
        this.maxProtocolVersion = maxProtocolVersion;
    }

    /**
     * @return Numeric representation of major server version.
     */
    public int getMajorVersion() {
        return (numericVersion / 1000000);
    }

    /**
     * @return Numeric representation of minor server version.
     */
    public int getMinorVersion() {
        return (numericVersion % 1000000) / 1000;
    }

    /**
     * Convert string into {@link ServerVersion} enumeration. The string version can contain
     * a {@code "-SNAPSHOT"} suffix to properly match the version.
     *
     * @param version String version to convert.
     * @param allowPrefixMatch If {@code true} then "1.0.x" version will be matched with "1.0" enum.
     * @return {@link ServerVersion} enumeration converted from string, or throws {@link IllegalArgumentException}.
     */
    public static @NonNull ServerVersion versionFromString(@NonNull String version, boolean allowPrefixMatch) {
        if (version.endsWith("-SNAPSHOT")) {
            version = version.substring(0, version.length() - 9);
        }
        // Try equal match at first.
        for (ServerVersion v : values()) {
            if (v.version.equals(version)) {
                return v;
            }
        }
        if (allowPrefixMatch) {
            // There's no exact match, try to find prefix.
            for (ServerVersion v : values()) {
                if (version.startsWith(v.version + ".")) {
                    return v;
                }
            }
        }
        throw new IllegalArgumentException("Unknown server version " + version);
    }
}
