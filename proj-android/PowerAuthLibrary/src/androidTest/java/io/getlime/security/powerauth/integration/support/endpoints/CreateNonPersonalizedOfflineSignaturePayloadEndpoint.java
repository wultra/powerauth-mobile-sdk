package io.getlime.security.powerauth.integration.support.endpoints;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

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

    public static class Response extends OfflineSignaturePayload {
    }
}
