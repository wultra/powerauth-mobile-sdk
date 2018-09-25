package io.getlime.security.powerauth.core;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * The <code>MigrationData</code> class contains data required for
 * protocol migration. The object is accessed from JNI code.
 */
public class MigrationData {

    public final int toVersion;

    // V3 Fields

    public final String v3CtrData;

    /**
     * Constructs data for migration to V3 protocol.
     *
     * @param ctrData initial value for hash-based counter. Base64 string is expected.
     * @return migration data constructed for migration to V3 protocol version
     */
    public static @NonNull MigrationData version3(@NonNull String ctrData) {
        return new MigrationData(ProtocolVersion.V3, ctrData);
    }

    /**
     * Private constructor
     *
     * @param toVersion specifies version of data for migration
     * @param v3CtrData initial value for hash-based counter
     */
    private MigrationData(ProtocolVersion toVersion, @Nullable String v3CtrData) {
        this.toVersion = toVersion.numericValue;
        this.v3CtrData = v3CtrData;
    }
}
