package io.getlime.security.powerauth.integration.support.v10.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

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

        private long applicationId;
        private String data;

        public long getApplicationId() {
            return applicationId;
        }

        public void setApplicationId(long applicationId) {
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
