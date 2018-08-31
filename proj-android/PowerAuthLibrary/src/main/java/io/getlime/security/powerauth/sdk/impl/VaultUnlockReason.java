/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk.impl;


/**
 * Constants for Vault Unlock reasons.
 */
public class VaultUnlockReason {

    public static final String PASSWORD_VALIDATE = "PASSWORD_VALIDATE";
    public static final String PASSWORD_CHANGE = "PASSWORD_CHANGE";
    public static final String ADD_BIOMETRY = "ADD_BIOMETRY";
    public static final String FETCH_ENCRYPTION_KEY = "FETCH_ENCRYPTION_KEY";
    public static final String SIGN_WITH_DEVICE_PRIVATE_KEY = "SIGN_WITH_DEVICE_PRIVATE_KEY";

    /**
     Prevents class instantiation.
     */
    private VaultUnlockReason() { }
}
