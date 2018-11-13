package io.getlime.security.powerauth.shadow;

import org.robolectric.annotation.Implements;

import io.getlime.security.powerauth.core.Session;

/**
 * Shadow class (Robolectric mock) of {@link Session}.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@Implements(Session.class)
public class ShadowSession {

    public ShadowSession() {}

}
