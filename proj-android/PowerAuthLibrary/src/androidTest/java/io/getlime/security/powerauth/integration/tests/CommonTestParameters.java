package io.getlime.security.powerauth.integration.tests;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CommonTestParameters {
    public static Iterable<Object[]> getParameters() {
        List<Object[]> out = new ArrayList<>();
        for (String algorithm : Arrays.asList(
                "LEGACY_P256",
                "EC_P384",
                "EC_P384_ML_L3",
                "EC_P384_ML_L5")) {
            out.add(new Object[]{ algorithm });
        }
        return out;
    }
}
