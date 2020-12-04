package io.getlime.security.powerauth.integration.support.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import java.util.List;

import io.getlime.security.powerauth.integration.support.model.Application;

public class GetApplicationListEndpoint implements IServerApiEndpoint<GetApplicationListEndpoint.Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/application/list";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Empty request

    // Response

    public static class Response {
        private List<Application> applications;

        public List<Application> getApplications() {
            return applications;
        }

        public void setApplications(List<Application> applications) {
            this.applications = applications;
        }
    }
}
