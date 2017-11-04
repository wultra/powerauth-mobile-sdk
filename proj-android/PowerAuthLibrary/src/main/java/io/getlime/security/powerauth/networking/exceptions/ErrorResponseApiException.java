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

import io.getlime.core.rest.model.base.entity.Error;

/**
 * Signals that a REST connection failed with a known error. You can check
 * the reason of failure in the attached ErrorModel object.
 */
public class ErrorResponseApiException extends Exception {

    /**
     * Error response received from the server
     */
    private Error mErrorResponse;

    /**
     * Constructs a new exception with error received from server.
     *
     * @param errorResponse error received from server
     */
    public ErrorResponseApiException(Error errorResponse) {
        this.mErrorResponse = errorResponse;
    }

    /**
     * @return ErrorModel with failure reason
     */
    public Error getErrorResponse() {
        return mErrorResponse;
    }
}
