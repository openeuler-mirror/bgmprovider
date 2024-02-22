package org.openeuler.sm4;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class SM4GCMTest {
    // Initialization Vector
    private static final byte[] IV = toBytes("00001234567800000000ABCD");
    // Key
    private static final byte[] KEY = toBytes("0123456789ABCDEFFEDCBA9876543210");
    // Plaintext
    private static final byte[] PLAIN_TEXT = toBytes(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB" +
                    "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
                    "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF" +
                    "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
    // Associated Data
    private static final byte[] AAD = toBytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");

    // CipherText
    private static final byte[] CIPHER_TEXT = toBytes(
            "17F399F08C67D5EE19D0DC9969C4BB7D" +
                    "5FD46FD3756489069157B282BB200735" +
                    "D82710CA5C22F0CCFA7CBF93D496AC15" +
                    "A56834CBCF98C397B4024A2691233B8D");

    // Authentication Tag
    private static final byte[] AUTH_TAG = toBytes("83DE3541E4C2B58177E065A9BF7B62EC");

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec ivParameterSpec = new GCMParameterSpec(AUTH_TAG.length * 8, IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        cipher.updateAAD(AAD);
        byte[] encryptedBytes = cipher.doFinal(PLAIN_TEXT);

        // test length
        Assert.assertEquals(CIPHER_TEXT.length + AUTH_TAG.length, encryptedBytes.length);

        // test cipher text
        byte[] actualCipherText = new byte[CIPHER_TEXT.length];
        System.arraycopy(encryptedBytes, 0, actualCipherText, 0, actualCipherText.length);
        Assert.assertArrayEquals(CIPHER_TEXT, actualCipherText);

        // test authentication tag
        byte[] actualAuthTag = new byte[AUTH_TAG.length];
        System.arraycopy(encryptedBytes, CIPHER_TEXT.length, actualAuthTag, 0, actualAuthTag.length);
        Assert.assertArrayEquals(AUTH_TAG, actualAuthTag);
    }

    @Test
    public void testEncryptEmptyBytesAndDecrypt() throws Exception {
        byte[] keyByes = {20, 0, 99, 14, -88, 114, -1, -57, -31, 45, -99, -1, 31, -124, -26, -35};
        byte[] iv = {95, 69, -11, 35, -56, 20, -51, 24, 118, -29, -57, 31};
        byte[] aad = {0, 0, 0, 0, 0, 0, 0, 1, 23, 1, 1, 0, 0};
        int tagSize = 16;
        byte[] sourceBytes = new byte[0];
        byte[] expectEncryptedBytes = new byte[]{
                -94, 22, 46, -44, -68, 4, 56, 100, -45, 48, 63, 51, 0, 15, -34, 22
        };
        SecretKey key = new SecretKeySpec(keyByes, "SM4");
        GCMParameterSpec spec = new GCMParameterSpec(tagSize * 8, iv);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec, new SecureRandom());
        cipher.updateAAD(aad);
        byte[] encryptedBytes = cipher.doFinal(sourceBytes);
        Assert.assertArrayEquals(expectEncryptedBytes, encryptedBytes);

        cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, spec, new SecureRandom());
        cipher.updateAAD(aad);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        Assert.assertArrayEquals(sourceBytes, decryptedBytes);
    }

    @Test
    public void testDecrypt() throws Exception {
        byte[] encryptedBytes = new byte[CIPHER_TEXT.length + AUTH_TAG.length];
        System.arraycopy(CIPHER_TEXT, 0, encryptedBytes, 0, CIPHER_TEXT.length);
        System.arraycopy(AUTH_TAG, 0, encryptedBytes, CIPHER_TEXT.length, AUTH_TAG.length);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec ivParameterSpec = new GCMParameterSpec(AUTH_TAG.length * 8, IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        cipher.updateAAD(AAD);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        Assert.assertArrayEquals(PLAIN_TEXT, decryptedBytes);
    }

    private static byte[] toBytes(String str) {
        int length = str.length();
        char[] charArray = str.toCharArray();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) Short.parseShort(
                    charArray[i] + "" + charArray[i + 1], 16);
        }
        return bytes;
    }
}
