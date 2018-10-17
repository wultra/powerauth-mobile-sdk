package io.getlime.security.powerauth.core;

/**
 * The <code>ProtocolVersion</code> enum defines PowerAuth protocol version. The main difference
 * between V2 & V3 is that V3 is using hash-based counter instead of linear one,
 * and all E2EE tasks are now implemented by ECIES.
 *
 * This version of SDK is supporting V2 protocol in very limited scope, where only
 * the V2 signature calculations are supported. Basically, you cannot connect
 * to V2 servers with V3 SDK.
 */
public enum ProtocolVersion {
    /**
     * Version is not available. This enumeration can be returned from some APIs,
     * when the value cannot be determined.
     */
    NA(0),

    /**
     * Protocol version 2
     */
    V2(2),

    /**
     * Protocol version 3
     */
    V3(3);

    /**
     * The value associated to the enumeration.
     */
    public final int numericValue;

    ProtocolVersion(int numericValue) {
        this.numericValue = numericValue;
    }
}
