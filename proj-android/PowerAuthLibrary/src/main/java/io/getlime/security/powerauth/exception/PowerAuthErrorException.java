/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.exception;

/**
 * Will be thrown, or will be returned to listener, in case that requested operation fails
 * on an error.
 */
public class PowerAuthErrorException extends Exception {

    /**
     * Integer constant from {@link PowerAuthErrorCodes} class.
     */
    @PowerAuthErrorCodes
    private int powerAuthErrorCode;

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode) {
        this.powerAuthErrorCode = powerAuthErrorCode;
    }

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     * @param message String with detailed error description.
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode, String message) {
        super(message);
        this.powerAuthErrorCode = powerAuthErrorCode;
    }

    /**
     * @return Integer constant from {@link PowerAuthErrorCodes}, describing the reason of failure.
     */
    @PowerAuthErrorCodes
    public int getPowerAuthErrorCode() {
        return powerAuthErrorCode;
    }
}
