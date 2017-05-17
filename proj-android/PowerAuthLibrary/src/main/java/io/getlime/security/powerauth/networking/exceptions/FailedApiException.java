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

package io.getlime.security.powerauth.networking.exceptions;

/**
 * Signals that a REST connection failed with an unknown response from the server.
 * You can investigate a received HTTP response code and response body string
 * for more details.
 */
public class FailedApiException extends Exception {

    /**
     * HTTP response code
     */
    private int responseCode;
    /**
     * HTTP response body. The value may be null.
     */
    private String responseBody;

    /**
     * Constructs an exception with response code and response body.
     *
     * @param responseCode HTTP response code
     * @param responseBody HTTP response body
     */
    public FailedApiException(int responseCode, String responseBody) {
        this.responseCode = responseCode;
        this.responseBody = responseBody;
    }


    /**
     * Constructs an exception with message, response code and response body.
     *
     * @param message message from another exception
     * @param responseCode HTTP response code
     * @param responseBody HTTP response body
     */
    public FailedApiException(String message, int responseCode, String responseBody) {
        super(message);
        this.responseCode = responseCode;
        this.responseBody = responseBody;
    }

    /**
     * @return HTTP response code
     */
    public int getResponseCode() { return responseCode; }

    /**
     * @return HTTP response body. The returned value may be null.
     */
    public String getResponseBody() { return responseBody; }
}
