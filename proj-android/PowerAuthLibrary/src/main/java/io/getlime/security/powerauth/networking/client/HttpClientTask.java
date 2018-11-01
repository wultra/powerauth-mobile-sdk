package io.getlime.security.powerauth.networking.client;

import android.os.AsyncTask;
import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancellable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;

/**
 * The {@code ClientTask} class implements an actual HTTP request & response processing, with using
 * {@link AsyncTask} infrastructure.
 */
class HttpClientTask<TRequest, TResponse> extends AsyncTask<TRequest, Void, TResponse> implements ICancellable {

    private final HttpRequestHelper<TRequest, TResponse> httpRequestHelper;
    private final String baseUrl;
    private final IPrivateCryptoHelper cryptoHelper;
    private final INetworkResponseListener<TResponse> listener;
    private final PowerAuthClientConfiguration clientConfiguration;

    /**
     * If not null, then the task ended with an error.
     */
    private Throwable error;

    /**
     * @param httpRequestHelper request helper responsible for object serialization and deserialization
     * @param baseUrl base URL
     * @param clientConfiguration client configuration
     * @param cryptoHelper cryptographic helper
     * @param listener response listener
     */
    public HttpClientTask(
            @NonNull HttpRequestHelper<TRequest, TResponse> httpRequestHelper,
            @NonNull String baseUrl,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull IPrivateCryptoHelper cryptoHelper,
            @NonNull INetworkResponseListener<TResponse> listener) {
        this.httpRequestHelper = httpRequestHelper;
        this.baseUrl = baseUrl;
        this.cryptoHelper = cryptoHelper;
        this.clientConfiguration = clientConfiguration;
        this.listener = listener;
    }

    /**
     * Reads all bytes from an input stream.
     *
     * @param is input stream whose content will be converted
     * @return String received from input stream
     */
    private byte[] loadBytesFromInputStream(InputStream is) throws IOException {
        if (is == null) {
            return null;
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
            if (isCancelled()) {
                return null;
            }
        }
        return result.toByteArray();
    }

    @Override
    protected TResponse doInBackground(TRequest... tRequests) {
        try {
            // Prepare request data
            HttpRequestHelper.RequestData requestData = httpRequestHelper.buildRequest(baseUrl, cryptoHelper);

            // Create an URL connection
            final HttpURLConnection urlConnection = (HttpURLConnection) requestData.url.openConnection();
            final boolean securedUrlConnection = urlConnection instanceof HttpsURLConnection;

            // Setup the connection
            urlConnection.setRequestMethod(requestData.method);
            urlConnection.setDoOutput(true);
            urlConnection.setUseCaches(false);
            urlConnection.setConnectTimeout(clientConfiguration.getConnectionTimeout());
            urlConnection.setReadTimeout(clientConfiguration.getReadTimeout());
            for (Map.Entry<String, String> header : requestData.httpHeaders.entrySet()) {
                urlConnection.setRequestProperty(header.getKey(), header.getValue());
            }

            // ssl validation strategy
            if (securedUrlConnection) {
                final PA2ClientValidationStrategy clientValidationStrategy = clientConfiguration.getClientValidationStrategy();
                if (clientValidationStrategy != null) {
                    final HttpsURLConnection sslConnection = (HttpsURLConnection) urlConnection;
                    final SSLSocketFactory sslSocketFactory = clientValidationStrategy.getSSLSocketFactory();
                    if (sslSocketFactory != null) {
                        sslConnection.setSSLSocketFactory(sslSocketFactory);
                    }
                    final HostnameVerifier hostnameVerifier = clientValidationStrategy.getHostnameVerifier();
                    if (hostnameVerifier != null) {
                        sslConnection.setHostnameVerifier(hostnameVerifier);
                    }
                }
            } else {
                if (!clientConfiguration.isUnsecuredConnectionAllowed()) {
                    throw new SSLException("Connection to non-TLS endpoint is not allowed.");
                }
            }

            // Connect to endpoint
            urlConnection.getOutputStream().write(requestData.body);
            urlConnection.connect();

            // Get response code & try to get response body
            final int responseCode = urlConnection.getResponseCode();
            final boolean responseOk = responseCode / 100 == 2;

            // Get response bytes from input stream
            final InputStream inputStream = responseOk ? urlConnection.getInputStream() : urlConnection.getErrorStream();
            final byte[] responseData = loadBytesFromInputStream(inputStream);

            // Try to deserialize response
            TResponse response = httpRequestHelper.buildResponse(responseCode, responseData);
            return response;

        } catch (Throwable e) {
            error = e;
        }
        return null;
    }

    @Override
    protected void onCancelled() {
        super.onCancelled();
        listener.onCancel();
    }

    @Override
    protected void onPostExecute(TResponse response) {
        super.onPostExecute(response);
        if (error == null) {
            listener.onNetworkResponse(response);
        } else {
            listener.onNetworkError(error);
        }
    }

    @Override
    public void cancel() {
        this.cancel(true);
    }
}
