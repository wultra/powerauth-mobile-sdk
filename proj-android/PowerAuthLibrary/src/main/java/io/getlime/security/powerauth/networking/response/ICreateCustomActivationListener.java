package io.getlime.security.powerauth.networking.response;

import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateCustomResponse;

/**
 * @author Marcel Syrucek <marcel.syrucek@cleverlance.com>
 */

public interface ICreateCustomActivationListener {
    void onActivationCreateSucceed(ActivationCreateCustomResponse response);

    void onActivationCreateFailed(Throwable t);
}
