/*
 * Copyright (c) 2005, 2012, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 6209660 6383200
 * @summary Ensure that InvalidAlgorithmParameterException is
 * thrown as javadoc specified when parameters of the wrong
 * type are used.
 * @author Valerie Peng
 */

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PBEInvalidParamsTest {
    private final static String SunJCEProvider = "SunJCE";
    private static final String BGMJCEProvider = "BGMJCEProvider";

    private static final char[] PASSWORD = {'p', 'a', 's', 's'};
    private static final String[] PBE_NOT_SM4_ALGORITHMS = {
            "PBEWithMD5AndDES",
            "PBEWithSHA1AndDESede",
            "PBEWithSHA1AndRC2_40",
            "PBEWithSHA1AndRC2_128",
            "PBEWithSHA1AndRC4_40",
            "PBEWithSHA1AndRC4_128",
            // skip "PBEWithMD5AndTripleDES" since it requires Unlimited
            // version of JCE jurisdiction policy files.
            "PBEWithHmacSHA1AndAES_128",
            "PBEWithHmacSHA224AndAES_128",
            "PBEWithHmacSHA256AndAES_128",
            "PBEWithHmacSHA384AndAES_128",
            "PBEWithHmacSHA512AndAES_128"
            // skip "PBEWithHmacSHAxxxAndAES_256" since they require Unlimited
            // version of JCE jurisdiction policy files.
    };

    private static final String[] PBE_SM4_ALGORITHMS = {
            "PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
            "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
            "PBEWithHmacSM3AndSM4_CBC"
    };

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void testNotSM4() throws Exception {
        test(PBE_NOT_SM4_ALGORITHMS, SunJCEProvider);
    }

    @Test
    public void testSM4() throws Exception {
        test(PBE_SM4_ALGORITHMS, BGMJCEProvider);
    }

    private static final IvParameterSpec INVALID_PARAMS =
            new IvParameterSpec(new byte[8]);

    private static void test(String[] algorithms, String provider) throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD);
        for (int i = 0; i < algorithms.length; i++) {
            String algo = algorithms[i];
            System.out.println("=>testing " + algo);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algo);
            SecretKey key = skf.generateSecret(ks);
            Cipher c = Cipher.getInstance(algo, provider);
            try {
                c.init(Cipher.ENCRYPT_MODE, key, INVALID_PARAMS);
                throw new Exception("Test Failed: expected IAPE is " +
                        "not thrown for " + algo);
            } catch (InvalidAlgorithmParameterException iape) {
                continue;
            }
        }
        System.out.println("Test Passed");
    }
}