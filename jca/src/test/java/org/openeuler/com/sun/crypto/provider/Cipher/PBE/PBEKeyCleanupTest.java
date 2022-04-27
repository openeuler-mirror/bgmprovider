/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.com.sun.crypto.provider.Cipher.PBE;
/*
 * @test
 * @modules java.base/com.sun.crypto.provider:+open
 * @run main/othervm PBEKeyCleanupTest
 * @summary Verify that key storage is cleared
 */

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import java.lang.reflect.Field;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test that the array holding the key bytes is cleared when it is
 * no longer referenced by the key.
 */
public class PBEKeyCleanupTest {

    private final static String SunJCEProvider = "SunJCE";
    private final static String BGMJCEProvider = "BGMJCEProvider";

    private static final String PASS_PHRASE = "some hidden string";
    private static final int ITERATION_COUNT = 1000;
    private static final int KEY_SIZE = 128;

    private static final String[] PBE_SM4_ALGORITHMS = {
            "PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
            "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
            "PBEWithHmacSM3AndSM4_CBC",
            "PBKDF2WithHmacSM3",
    };

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void testNotSM4() throws Exception {
        testPBESecret("PBEWithMD5AndDES", SunJCEProvider);
        testPBKSecret("PBKDF2WithHmacSHA1", SunJCEProvider);
    }

    @Test(timeout = 10000L)
    public void testSM4() throws Exception {
        test(PBE_SM4_ALGORITHMS, BGMJCEProvider);
    }

    private void test(String[] algorithms, String provider) throws Exception {
        for (String algorithm : algorithms) {
            testPBKSecret(algorithm, provider);
        }
    }

    private static void testPBESecret(String algorithm, String provider) throws Exception {
        char[] password = new char[]{'f', 'o', 'o'};
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac =
                SecretKeyFactory.getInstance(algorithm, provider);

        testCleanupSecret(algorithm, keyFac.generateSecret(pbeKeySpec));
    }

    private static void testPBKSecret(String algorithm, String provider) throws Exception {
        byte[] salt = new byte[8];
        new Random().nextBytes(salt);
        char[] password = new char[]{'f', 'o', 'o'};
        PBEKeySpec pbeKeySpec = new PBEKeySpec(PASS_PHRASE.toCharArray(), salt,
                ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory keyFac =
                SecretKeyFactory.getInstance(algorithm, provider);

        testCleanupSecret(algorithm, keyFac.generateSecret(pbeKeySpec));
    }

    static void testCleanupSecret(String algorithm, SecretKey key) throws Exception {

        // Break into the implementation to observe the key byte array.
        Class<?> keyClass = key.getClass();
        Field keyField = keyClass.getDeclaredField("key");
        keyField.setAccessible(true);
        byte[] array = (byte[]) keyField.get(key);
        byte[] zeros = new byte[array.length];
        do {
            // Wait for array to be cleared;  if not cleared test will timeout
            System.out.printf("%s array: %s%n", algorithm, Arrays.toString(array));
            key = null;
            System.gc();        // attempt to reclaim the key
        } while (!Arrays.equals(zeros, array));
        System.out.printf("%s array: %s%n", algorithm, Arrays.toString(array));

        // Keep key and array alive
        key = new SecretKeySpec(array, "");
        System.out.println(Arrays.toString(key.getEncoded()));
    }
}



