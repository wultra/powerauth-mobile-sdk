/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.networking.ssl;

import android.annotation.SuppressLint;
import android.support.annotation.Nullable;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Unsafe implementation of HostnameVerifier and X509TrustManager SSL client validation {@link io.getlime.security.powerauth.networking.ssl.PA2ClientSslNoValidationStrategy} interface.
 * For debug/testing purposes only, e.g. when untrusted self-signed SSL certificate is used on server side.
 * <p>
 * It's strictly recommended to use this unsafe implementation of HostnameVerifier and X509TrustManager interfaces only in debug flavours of your application. Deploying to production
 * may cause "Security alert" in Google Developer Console. Please see <a href="https://support.google.com/faqs/answer/7188426">this</a> and
 * <a href="https://support.google.com/faqs/answer/6346016">this</a> Google Help Center articles for more details.
 * Beginning 1 March 2017, Google Play will block publishing of any new apps or updates that use an unsafe implementation of HostnameVerifier.
 * <p>
 * How to solve this problem for debug/production flavours in gradle build script:
 * <p>
 * 1. Define boolean type buildConfigField in flavour configuration.
 *
 * <pre>
 * <code>
 *   productFlavors {
 *      production {
 *          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'false'
 *      }
 *      debug {
 *          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'true'
 *      }
 *   }
 * </code>
 * </pre>
 *
 * 2. In code use this conditional initialization for {@link io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration.Builder} builder.
 *
 * <pre>
 * <code>
 *   PowerAuthClientConfiguration.Builder clientBuilder = new PowerAuthClientConfiguration.Builder();
 *   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
 *       clientBuilder.clientValidationStrategy(new PA2ClientSslNoValidationStrategy());
 *   }
 * </code>
 * </pre>
 *
 * 3. Set minifyEnabled to true for release buildType to enable code shrinking with ProGuard.
 */

public class PA2ClientSslNoValidationStrategy implements PA2ClientValidationStrategy {

    @Nullable
    @Override
    public SSLSocketFactory getSSLSocketFactory() {

        // Create a trust manager that does not validate certificate chains
        final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @SuppressLint("TrustAllX509TrustManager")
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            }

            @SuppressLint("TrustAllX509TrustManager")
            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[0];
            }
        }};

        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, null);
            return sc.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    @Nullable
    @Override
    public HostnameVerifier getHostnameVerifier() {
        return new HostnameVerifier() {

            @SuppressLint("BadHostnameVerifier")
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }
}
