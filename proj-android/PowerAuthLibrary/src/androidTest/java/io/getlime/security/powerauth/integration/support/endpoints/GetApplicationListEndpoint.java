package io.getlime.security.powerauth.integration.support.endpoints;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

public class GetApplicationListEndpoint implements IServerApiEndpoint<GetApplicationListResponse> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/application/list";
    }

    @NonNull
    @Override
    public String getHttpMethod() {
        return "POST";
    }

    @Nullable
    @Override
    public TypeToken<GetApplicationListResponse> getResponseType() {
        return TypeToken.get(GetApplicationListResponse.class);
    }
}
