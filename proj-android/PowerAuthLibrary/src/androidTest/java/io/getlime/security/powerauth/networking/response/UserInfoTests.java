/*
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.response;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class UserInfoTests {

    @Test
    public void testEmptyObjectCreation() throws Exception {
        UserInfo info = new UserInfo(null);
        assertNull(info.getSubject());
        assertNull(info.getName());
        assertNull(info.getGivenName());
        assertNull(info.getMiddleName());
        assertNull(info.getFamilyName());
        assertNull(info.getNickname());
        assertNull(info.getPreferredUsername());
        assertNull(info.getProfileUrl());
        assertNull(info.getPictureUrl());
        assertNull(info.getWebsiteUrl());
        assertNull(info.getEmail());
        assertFalse(info.isEmailVerified());
        assertNull(info.getPhoneNumber());
        assertFalse(info.isPhoneNumberVerified());
        assertNull(info.getGender());
        assertNull(info.getZoneInfo());
        assertNull(info.getLocale());
        UserAddress address = info.getAddress();
        assertNull(address);
        assertNull(info.getAllClaims().get("custom_claim"));
    }

    @Test
    public void testStandardClaims() throws Exception {
        final Date now = new Date(new Date().getTime()/1000*1000);
        UserInfo info = deserializeFromJson("{" +
                "    \"sub\": \"123456\"," +
                "    \"name\": \"John Jacob Doe\"," +
                "    \"given_name\": \"John\"," +
                "    \"family_name\": \"Doe\"," +
                "    \"middle_name\": \"Jacob\"," +
                "    \"nickname\": \"jjd\"," +
                "    \"preferred_username\" : \"JacobTheGreat\"," +
                "    \"profile\": \"https://jjd.com/profile\"," +
                "    \"picture\": \"https://jjd.com/avatar.jpg\"," +
                "    \"website\": \"https://jjd.com\"," +
                "    \"email\": \"jacob@jjd.com\"," +
                "    \"email_verified\": true," +
                "    \"gender\": \"male\"," +
                "    \"birthdate\": \"1984-02-21\"," +
                "    \"zoneinfo\": \"Europe/Prague\"," +
                "    \"locale\": \"en-US\"," +
                "    \"phone_number\": \"+1 (425) 555-1212\"," +
                "    \"phone_number_verified\":true," +
                "    \"address\": {" +
                "        \"formatted\": \"Belehradska 858/23\\r\\n120 00 Prague - Vinohrady\\r\\nCzech Republic\"," +
                "        \"street_address\": \"Belehradska 858/23\\r\\nVinohrady\"," +
                "        \"locality\": \"Prague\"," +
                "        \"region\": \"Prague\"," +
                "        \"postal_code\": \"12000\"," +
                "        \"country\": \"Czech Republic\"" +
                "    }," +
                "    \"updated_at\": " + now.getTime()/1000 + "," +
                "    \"custom_claim\": \"Hello world!\"" +
                "}");
        assertNotNull(info);
        assertEquals("123456", info.getSubject());
        assertEquals("John Jacob Doe", info.getName());
        assertEquals("John", info.getGivenName());
        assertEquals("Jacob", info.getMiddleName());
        assertEquals("Doe", info.getFamilyName());
        assertEquals("jjd", info.getNickname());
        assertEquals("JacobTheGreat", info.getPreferredUsername());
        assertEquals("https://jjd.com/profile", info.getProfileUrl());
        assertEquals("https://jjd.com/avatar.jpg", info.getPictureUrl());
        assertEquals("https://jjd.com", info.getWebsiteUrl());
        assertEquals("jacob@jjd.com", info.getEmail());
        assertEquals(now, info.getUpdatedAt());
        assertTrue(info.isEmailVerified());
        assertEquals("+1 (425) 555-1212", info.getPhoneNumber());
        assertTrue(info.isPhoneNumberVerified());
        assertEquals("male",info.getGender());
        assertEquals("Europe/Prague", info.getZoneInfo());
        assertEquals("en-US", info.getLocale());
        UserAddress address = info.getAddress();
        assertNotNull(address);
        assertEquals("Belehradska 858/23\n120 00 Prague - Vinohrady\nCzech Republic", address.getFormatted());
        assertEquals("Belehradska 858/23\nVinohrady", address.getStreet());
        assertEquals("Prague", address.getLocality());
        assertEquals("Prague", address.getRegion());
        assertEquals("12000", address.getPostalCode());
        assertEquals("Czech Republic", address.getCountry());
        assertEquals("Hello world!", info.getAllClaims().get("custom_claim"));

        // Construct 1984-02-21
        final Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.MONTH, 2);
        calendar.set(Calendar.DAY_OF_MONTH, 21);
        calendar.set(Calendar.YEAR, 1984);
        assertEquals(calendar.getTime(), info.getBirthdate());

        info = deserializeFromJson("{" +
                "    \"email_verified\": false,\n" +
                "    \"phone_number_verified\":false\n" +
                "}");
        assertFalse(info.isPhoneNumberVerified());
        assertFalse(info.isEmailVerified());
    }

    private UserInfo deserializeFromJson(String testData) {
        if (gson == null) {
            gson = new GsonBuilder().create();
        }
        final Map<String, Object> map = gson.fromJson(testData, new TypeToken<Map<String, Object>>(){}.getType());
        return new UserInfo(map);
    }

    private Gson gson;
}
