package io.getlime.security.powerauth.shadow;

import android.support.annotation.Nullable;

import org.robolectric.annotation.Implements;

import io.getlime.security.powerauth.networking.response.ISavePowerAuthStateListener;
import io.getlime.security.powerauth.sdk.impl.DefaultSavePowerAuthStateListener;

/**
 * Shadow class (Robolectric mock) of {@link DefaultSavePowerAuthStateListener}.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@Implements(DefaultSavePowerAuthStateListener.class)
public class ShadowDefaultSavePowerAuthStateListener implements ISavePowerAuthStateListener {

    @Override
    public byte[] serializedState(String instanceId) {
        return new byte[0];
    }

    @Override
    public void onPowerAuthStateChanged(@Nullable String instanceId, byte[] serializedState) {

    }
}
