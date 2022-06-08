package io.getlime.security.powerauth.integration.support.v13.endpoints;

import com.google.gson.reflect.TypeToken;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;

public class CreateNonPersonalizedOfflineSignaturePayloadEndpoint implements IServerApiEndpoint<CreateNonPersonalizedOfflineSignaturePayloadEndpoint.Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/signature/offline/non-personalized/create";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Request

    public static class Request {

        private String applicationId;
        private String data;

        public String getApplicationId() {
            return applicationId;
        }

        public void setApplicationId(String applicationId) {
            this.applicationId = applicationId;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }

    // Response

    public static class Response extends OfflineSignaturePayload {
    }
}
