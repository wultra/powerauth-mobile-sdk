/*
 * Copyright 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.client;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.google.gson.reflect.TypeToken;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class JsonSerializationTest {

    public static class TestModel {
        public String text;
        TestModel(String text) {
            this.text = text;
        }
    }

    @Test
    public void testJwtSerialize() throws Exception {
        final JsonSerialization serialization = new JsonSerialization();
        TestModel data = serialization.deserializeJwtObject("eyJ0ZXh0Ijoixb7DtMW-w6QifQ", new TypeToken<>(){});
        assertEquals("žôžä", data.text);
        String serializedData = serialization.serializeJwtObject(data);
        assertEquals("eyJ0ZXh0Ijoixb7DtMW-w6QifQ", serializedData);
        data = serialization.deserializeJwtObject("eyJ0ZXh0Ijoi8J-SqT8_In0", new TypeToken<>(){});
        assertEquals("\uD83D\uDCA9??", data.text);
        serializedData = serialization.serializeJwtObject(data);
        assertEquals("eyJ0ZXh0Ijoi8J-SqT8_In0", serializedData);
    }
}
