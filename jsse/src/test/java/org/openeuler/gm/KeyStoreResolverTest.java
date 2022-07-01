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
package org.openeuler.gm;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;

public class KeyStoreResolverTest extends BaseTest {
    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String KEY_ALIAS = "a";
    private static final String PKCS12 = "PKCS12";
    private static final String JKS = "JKS";

    // PKCS12 keystore file
    private static final String PKCS12_FILE =
            "3082049b0201033082044506092a864886f70d010701a0820436048204323082" +
            "042e3082017c06092a864886f70d010701a082016d0482016930820165308201" +
            "61060b2a864886f70d010c0a0102a082011830820114306f060b2a811ccf5506" +
            "01040105023060303c060b2a811ccf55060104010501302d0414c66f2b0bd852" +
            "e0633446d42610042d4bd5c2f2a002022710020110300e060a2a811ccf550183" +
            "11030105003020060c2a811ccf55060104010c010104105804a073e240139d47" +
            "ea2dfe147070290481a00fee1328216e4af58b94fad107589f79e644ab3f54e7" +
            "484220379a8c2f8ba6f717475b1142d6fcfa3d7cc318b6074ac3bd5a010da91c" +
            "99640e45eec1dd53f3664fd3fa961215157e5c2354aac095fe70d48eccf9f939" +
            "c9cf61e0d4411a3f6e6a3687cc86511f9d0db50059920cc50a7a2ff1c8c0f447" +
            "bdb3f84d6e4ee0b54c1c8671a7ccbc1d4b33c104d0c4533e1a25673bb2a90a17" +
            "0167b07c5191051238bc3136301106092a864886f70d01091431041e02006130" +
            "2106092a864886f70d0109153114041254696d65203136353037393230383136" +
            "3838308202aa06092a864886f70d010706a082029b3082029702010030820290" +
            "06092a864886f70d010701306f060b2a811ccf550601040105023060303c060b" +
            "2a811ccf55060104010501302d0414881c31ece0ad114d8b0063b97c9eebcd8b" +
            "50d22402022710020110300e060a2a811ccf55018311030105003020060c2a81" +
            "1ccf55060104010c01010410b3316915a4de460af928e472268ccd4a80820210" +
            "da68444fd983bdd2c44e23c5ce1ae2a3f0283ed93b67aeab572eac0d76a896f3" +
            "fb8fffe7c2edadbd584013b408fca72b02a069ca7b07e27d94af3cc053af2bca" +
            "f8c5741748fd689f326860938c43f1abbf87ff6e90b7b787c8304b9c084f3355" +
            "68d6b6183e7832782852e716b81aa259e0ff7c22bb910a92026f695a6559bdf7" +
            "dfb1c948efb9cad2969ea0685e127e8435fcfd5d2f540801fb26d49b15cd80f8" +
            "f864247f9351c174a9f0315481369a50e18c26a2225b49faaa26f42db3c5d2fe" +
            "e3b96c0e8563e384a3541ce9dad8641d84e2429c97977a63c1031c100a6cfd33" +
            "178c2ddbed001d154ace32ed8b3454b0280cb2dba752be5254585f2d415db068" +
            "faedaf2961e5b7eddc61c2fc897c9e9b32157900490e7f3f7fa0a7db7c97d864" +
            "54e08170ac8c74e82204e451295fa7e03897618e9792b28d1d56d13c781e9f8c" +
            "a86d2b949d4ff092c88ef864de61b56e50e6848aafb9e2c9c8aef6617aa557e4" +
            "d52ccb6560e67c5da5832a4b64586e4ae92f8929273cdd9204da534d51118f94" +
            "6cd608a59feff94722c17d2807db3886618e7bf3fd5c3e1bee444d3bec123c11" +
            "1019495fc34e524404b8219a6197cd75d02aa466967e95a4c16f5491bf8764bf" +
            "933376fe15ad91507afa8eb8863d791d763e827c3ef0fd79781a7cd24917a08a" +
            "05021da54f318ba6ad417b96431803de90117346ed1d894b0e2fbfce4a82670b" +
            "00a04a46a4fbac2400f4970cb0b3455d304d3030300c06082a811ccf55018311" +
            "05000420700813dbee63b8835192918d112d6474da4e75252961678361cfd116" +
            "c43e315a0414a1788c03cfe1fc96355d04828b350482563aaa0f02030186a0";

    // JKS keystore file
    private static final String JKS_FILE =
            "feedfeed00000002000000010000000100016100000180b75331f0000000d430" +
            "81d1300e060a2b060104012a0211010105000481be43c62882695a4c9f3463a9" +
            "e2c6753eb49364e5eb97db641b53d764fa364ea7d24e4943aee729d5f6d7a2fc" +
            "6676086f3b3d071535e7b24726a74ded4ea2234731b1f50ab1ea733aab86de93" +
            "a6b4d44487a98948b8834a40be25139bf4731b2d166c988a1cdde3e4e658b84d" +
            "de7e4eba33449537c1f7a071765d895566d064b07531118e418261d8a27c87eb" +
            "1cf84084dc7f07c1d6cc673dad4b32bfb79b433dbf9e6aea2f0d537f16a13cc2" +
            "88ff6dc8d0c0ff1d21b038e239f4674ffcead2000000010005582e3530390000" +
            "01a4308201a030820145a00302010202140c9d83bf80df230b5330623694d337" +
            "768b64a61b300a06082a811ccf550183753040310b300906035504061302434e" +
            "310e300c060355040a0c05546573744f310f300d060355040b0c06546573744f" +
            "553110300e06035504030c07534d322d454e43301e170d323230343234303631" +
            "3230355a170d3332303432313036313230355a3040310b300906035504061302" +
            "434e310e300c060355040a0c05546573744f310f300d060355040b0c06546573" +
            "744f553110300e06035504030c07534d322d454e433059301306072a8648ce3d" +
            "020106082a811ccf5501822d03420004d57137a5f642a19a577b109e23dbf616" +
            "fe7394642c4262b63755c1b441f59f7e9bd8c3c9b48bf4ac95de09353454b62a" +
            "d123b142a052302b57f6cea33fdc1177a31d301b30090603551d130402300030" +
            "0e0603551d0f0101ff040403020338300a06082a811ccf550183750349003046" +
            "022100be15fff7766c01f7be46be044ea839e2cb74fac8bf7bfc20ca23660072" +
            "2289bc022100cb97363105a8be703280893c793620d053ae2c2146c951a8dfc6" +
            "312bcf95554006bb3eb0ea85227b5069dd757a8090bc66a233ba";

    private byte[] getBytes(String file) {
        byte[] p12 = new byte[file.length() / 2];
        for (int i = 0; i < p12.length; i++) {
            p12[i] = Integer.valueOf(file.substring(2 * i, 2 * i + 2), 16)
                    .byteValue();
        }
        return p12;
    }

    private KeyStore loadKeyStore(String file, String type) throws Exception {
        byte[] p12 = getBytes(file);
        KeyStore keyStore = KeyStore.getInstance(type);
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(p12)) {
            keyStore.load(inputStream, PASSWORD);
        }
        return keyStore;
    }

    private void assertKeyStore(KeyStore keyStore) throws Exception {
        Assert.assertNotNull(keyStore.getCertificate(KEY_ALIAS));
        Assert.assertNotNull(keyStore.getKey(KEY_ALIAS, PASSWORD));
    }

    @Test
    public void testDualFormatPKCS12() throws Exception {
        KeyStore p12KeyStore = loadKeyStore(PKCS12_FILE, PKCS12);
        assertKeyStore(p12KeyStore);
        KeyStore jksKeyStore = loadKeyStore(PKCS12_FILE, JKS);
        assertKeyStore(jksKeyStore);
    }

    @Test
    public void testDualFormatJKS() throws Exception {
        KeyStore jksKeyStore = loadKeyStore(JKS_FILE, JKS);
        assertKeyStore(jksKeyStore);
        KeyStore p12KeyStore = loadKeyStore(JKS_FILE, PKCS12);
        assertKeyStore(p12KeyStore);
    }
}
