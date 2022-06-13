package io.getlime.security.powerauth.integration.support.v10.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;
import java.util.List;

import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;

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
    public static class ApplicationV10 {

        private Long id;
        private String applicationName;
        private List<String> applicationRoles;

        public ApplicationV10() {
        }

        public Long getApplicationId() {
            return id;
        }

        public void setApplicationId(Long applicationId) {
            this.id = applicationId;
        }

        public String getApplicationName() {
            return applicationName;
        }

        public void setApplicationName(String applicationName) {
            this.applicationName = applicationName;
        }

        public List<String> getApplicationRoles() {
            return applicationRoles;
        }

        public void setApplicationRoles(List<String> applicationRoles) {
            this.applicationRoles = applicationRoles;
        }

        public Application toApplication() {
            final Application app = new Application();
            app.setApplicationId(id.toString());
            app.setApplicationName(applicationName);
            app.setApplicationRoles(applicationRoles);
            return app;
        }
    }

    public static class Response {
        private List<ApplicationV10> applications;

        public List<ApplicationV10> getApplications() {
            return applications;
        }

        public void setApplications(List<ApplicationV10> applications) {
            this.applications = applications;
        }

        public List<Application> getModelApplications() {
            ArrayList<Application> result = new ArrayList<>(applications.size());
            for (ApplicationV10 applicationV10: applications) {
                result.add(applicationV10.toApplication());
            }
            return result;
        }
    }
}
