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

package io.getlime.security.powerauth.core;

/**
 The SignatureFactor constants defines factors involved in the signature
 computation. The factor types are tightly coupled with SignatureUnlockKeys
 class.
 */
public class SignatureFactor
{
    /**
     The possession factor, you have to provide possessionUnlocKey.
     */
    public static final int Possession = 0x0001;
    /**
     The knowledge factor, you have to provide userPassword
     */
    public static final int Knowledge  = 0x0010;
    /**
     The biometry factor, you have to provide biometryUnlockKey.
     */
    public static final int Biometry   = 0x0100;

    /**
     2FA, with using possession and knowledge factors.
     */
    public static final int Possession_Knowledge            = 0x0011;
    /**
     2FA, with using possession and biometric factors.
     */
    public static final int Possession_Biometry             = 0x0101;
    /**
     3FA, with using all supported factors.
     */
    public static final int Possession_Knowledge_Biometry   = 0x0111;
    /**
     The PrepareForVaultUnlock flag can be combined with any signature factor and
     notifies Session about operation which will lead to vault unlock.
     */
    @Deprecated
    public static final int PrepareForVaultUnlock           = 0x1000;
    
    /**
     Prevents class instantiation.
     */
    private SignatureFactor() { }
}