/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
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
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

public class SM3Test {
    private static String plainText = "helloworldhello";
    private static String algo = "SM3";
    private static byte[] expectRes = new byte[]{40, -103, -71, 4, -80, -49, 94, 112, 11, -75, -66, 121, 63, 80, 62, -14, -45, -75, -34, 66, -77, -34, -26, 26, 33, -23, 45, 52, -74, 67, -18, 118};

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo);
        md.update(plainText.getBytes(StandardCharsets.UTF_8));
        MessageDigest md2 = (MessageDigest) md.clone();
        byte[] res = md2.digest("w".getBytes(StandardCharsets.UTF_8));
        if (!Arrays.equals(res, expectRes)) {
            throw new RuntimeException("sm3 failed");
        }
    }

    @Test
    public  void randTest() throws Exception {
        String[] randResult = {
                "bb372719ca7e1f9bb4f671aa23310c8aeef3896ccb1974f8e827aed5c143b51",
                "8025d533e91c706091e12d5a70ae1ebf2fd374cfab59715e5c44374eadcbeeb8",
                "4f93d8a65b7042fa32f5002aae0767031781aab9c12fe9ea1aaeeec97831ee84",
                "dc6161b7a44c54d4d58866936a9a9285b1277008a59ad23b03e43abc83a153e5",
                "c128a4b67287a406e13c1188e598ee29b5c030c39f0ee6ef6b11633f671a6204",
                "8fedd713e8fcaa4b4a7c6c723528d4078dc6079a80fd8157776b01d63b4a11d3",
                "d95e309157a6566c0c25354fe775383bcc1e282b83cba88d8dd8460b0203a470",
                "a386e798f3d7c20aadfb0edf4398f2350b29efdce8d8cd306d55cc06bb6dca2e",
                "4b46088bacfc5c34a34507f3e1dfec8499543e0bb0627acbff852a1e5a19e6e1",
                "7e648ed453916e4386971843f4c1f0bced78c5e1594d515d91c08addc549f78e",
                "6f278f6d2092e20bc462aa1a5cd1b7fc2b094210fe088bf0e28d500ca989238a",
                "379effbea490204a903aeaaffa670313857252f88d90a2cf3cff10b2abbe85",
                "9e2b29269c4595d7da99a2510890566c70e46dc34fdccb7db65e88364714d8fb",
                "9dfd9c557ccc664cba5ecfb7407e443467113dd3e12439a37c8a930d2672be84",
                "1bcbe5b6f709deda3cbe72367fa173d3f87fb96b747e86cc2fa2fb0e81f3ab23",
                "58e55da9c229ff374f1d9bf2996b12862b9e9d4b8cc2a9b4a44011864c22f524",
                "6f0d9f308ec113f35d0a04c32edaa8b21d9a35b1811b62850e89f21f3112c382",
                "3f8e2c0985ecb8944a8692af9c5b45510c30d08a5a7721923ecbcf2aa03b8181",
                "a020a69ae6c9f98aa8cdf5545d7830df4af739eaef89ecd85cc9a268f505cea3",
                "b4f2c073896cca2468448917a641ea4aac641cee1b819eb02024cc1ae325005d"
        };
        Random rnd = new Random();
        rnd.setSeed(1); // Don't change the random number seed
        MessageDigest md = MessageDigest.getInstance("SM3");
        for (int i=0; i < 20; i++) {
            String str = getRandomString(rnd.nextInt(999999), rnd);
            md.update(str.getBytes(StandardCharsets.UTF_8));
            byte[] res = md.digest();
            String resStr = (new BigInteger(1, res)).toString(16);
            if (!resStr.equals(randResult[i])) {
                throw new RuntimeException("sm3 failed");
            }
        }
    }

    public static String getRandomString(int length, Random random){
        String str;
        str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }
}
