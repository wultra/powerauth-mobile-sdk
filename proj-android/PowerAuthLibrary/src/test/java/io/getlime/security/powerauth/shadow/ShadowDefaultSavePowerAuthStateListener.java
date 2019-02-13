package io.getlime.security.powerauth.shadow;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import org.robolectric.annotation.Implements;

import io.getlime.security.powerauth.sdk.impl.ISavePowerAuthStateListener;
import io.getlime.security.powerauth.sdk.impl.DefaultSavePowerAuthStateListener;

/**
 * Shadow class (Robolectric mock) of {@link DefaultSavePowerAuthStateListener}.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@Implements(DefaultSavePowerAuthStateListener.class)
public class ShadowDefaultSavePowerAuthStateListener implements ISavePowerAuthStateListener {

    @Override
    public @Nullable byte[] serializedState(@NonNull String instanceId) {
        return new byte[0];
    }

    @Override
    public void onPowerAuthStateChanged(@NonNull String instanceId, @NonNull byte[] serializedState) {

    }
}
