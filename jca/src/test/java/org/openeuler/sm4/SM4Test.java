package org.openeuler.sm4;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;

/**
 * SM4 full test
 */
public class SM4Test {
    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        try {
            Class<?> clazz = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider bcProvider = (Provider) clazz.newInstance();
            Security.insertProviderAt(bcProvider, 2);
        } catch (Exception e) {
            System.err.println("BouncyCastleProvider does not exist");
        }
    }

    @Test
    public void test() throws Exception {
        if (Security.getProvider("BC") == null) {
            System.out.println("Skip test, BouncyCastleProvider does not exist");
            return;
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        test("SM4/CBC/NOPADDING", key, 16, 64);
        test("SM4/CBC/pkcs5padding", key, 16, 11);
        test("SM4/CBC/pkcs5padding", key, 16, 32);
        testUpdate("SM4/CBC/NOPADDING", key, 16, 15);
        testUpdate("SM4/CBC/NOPADDING", key, 16, 16);
        testUpdate("SM4/CBC/NOPADDING", key, 16, 31);
        testUpdate("SM4/CBC/NOPADDING", key, 16, 32);
        testUpdate("SM4/CBC/pkcs5padding", key, 16, 15);
        testUpdate("SM4/CBC/pkcs5padding", key, 16, 16);
        testUpdate("SM4/CBC/pkcs5padding", key, 16, 31);
        testUpdate("SM4/CBC/pkcs5padding", key, 16, 32);
        testUpdateAndDofinal("SM4/CBC/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CBC/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CBC/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CBC/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CBC/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CBC/pkcs5padding", key, 16, 32, 18);

        test("SM4/CFB/NOPADDING", key, 16, 128);
        test("SM4/CFB/pkcs5padding", key, 16, 22);
        test("SM4/CFB/pkcs5padding", key, 16, 32);
        testUpdate("SM4/CFB/NOPADDING", key, 16, 15);
        testUpdate("SM4/CFB/NOPADDING", key, 16, 16);
        testUpdate("SM4/CFB/NOPADDING", key, 16, 31);
        testUpdate("SM4/CFB/NOPADDING", key, 16, 32);
        testUpdate("SM4/CFB/pkcs5padding", key, 16, 15);
        testUpdate("SM4/CFB/pkcs5padding", key, 16, 16);
        testUpdate("SM4/CFB/pkcs5padding", key, 16, 31);
        testUpdate("SM4/CFB/pkcs5padding", key, 16, 32);
        testUpdateAndDofinal("SM4/CFB/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CFB/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CFB/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CFB/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CFB/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CFB/pkcs5padding", key, 16, 32, 18);


        test("SM4/CTS/NOPADDING", key, 16, 32);
        test("SM4/CTS/NOPADDING", key, 16, 33);
        test("SM4/CTS/pkcs5padding", key, 16, 11);
        test("SM4/CTS/pkcs5padding", key, 16, 32);
        testUpdate("SM4/CTS/NOPADDING", key, 16, 15);
        testUpdate("SM4/CTS/NOPADDING", key, 16, 16);
        testUpdate("SM4/CTS/NOPADDING", key, 16, 31);
        testUpdate("SM4/CTS/NOPADDING", key, 16, 32);
        testUpdate("SM4/CTS/pkcs5padding", key, 16, 15);
        testUpdate("SM4/CTS/pkcs5padding", key, 16, 16);
        testUpdate("SM4/CTS/pkcs5padding", key, 16, 31);
        testUpdate("SM4/CTS/pkcs5padding", key, 16, 32);
        testUpdateAndDofinal("SM4/CTS/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CTS/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CTS/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CTS/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CTS/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CTS/pkcs5padding", key, 16, 32, 18);


        test("SM4/CTR/NOPADDING", key, 8, 11);
        test("SM4/CTR/NOPADDING", key, 9, 13);
        test("SM4/CTR/NOPADDING", key, 10, 7);
        test("SM4/CTR/NOPADDING", key, 11, 19);
        test("SM4/CTR/NOPADDING", key, 12, 21);
        test("SM4/CTR/NOPADDING", key, 13, 11);
        test("SM4/CTR/NOPADDING", key, 14, 12);
        test("SM4/CTR/NOPADDING", key, 15, 14);
        test("SM4/CTR/NOPADDING", key, 16, 15);
        test("SM4/CTR/pkcs5padding", key, 16, 15);
        test("SM4/CTR/pkcs5padding", key, 16, 16);
        testUpdate("SM4/CTR/NOPADDING", key, 16, 15);
        testUpdate("SM4/CTR/NOPADDING", key, 16, 16);
        testUpdate("SM4/CTR/NOPADDING", key, 16, 31);
        testUpdate("SM4/CTR/NOPADDING", key, 16, 32);
        testUpdate("SM4/CTR/pkcs5padding", key, 16, 15);
        testUpdate("SM4/CTR/pkcs5padding", key, 16, 16);
        testUpdate("SM4/CTR/pkcs5padding", key, 16, 31);
        testUpdate("SM4/CTR/pkcs5padding", key, 16, 32);
        testUpdateAndDofinal("SM4/CTR/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/CTR/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/CTR/NOPADDING", key, 16, 15, 5);
        testUpdateAndDofinal("SM4/CTR/NOPADDING", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CTR/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/CTR/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/CTR/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/CTR/pkcs5padding", key, 16, 32, 18);


        test("SM4/OFB/NOPADDING", key, 16, 32);
        test("SM4/OFB/pkcs5padding", key, 16, 15);
        test("SM4/OFB/pkcs5padding", key, 16, 32);
        testUpdate("SM4/OFB/NOPADDING", key, 16, 15);
        testUpdate("SM4/OFB/NOPADDING", key, 16, 16);
        testUpdate("SM4/OFB/NOPADDING", key, 16, 31);
        testUpdate("SM4/OFB/NOPADDING", key, 16, 32);
        testUpdate("SM4/OFB/pkcs5padding", key, 16, 15);
        testUpdate("SM4/OFB/pkcs5padding", key, 16, 16);
        testUpdate("SM4/OFB/pkcs5padding", key, 16, 31);
        testUpdate("SM4/OFB/pkcs5padding", key, 16, 32);
        testUpdateAndDofinal("SM4/OFB/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/OFB/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/OFB/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/OFB/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/OFB/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/OFB/pkcs5padding", key, 16, 32, 18);


        test("SM4/ECB/NOPADDING", key, 0, 16);
        test("SM4/ECB/pkcs5padding", key, 0, 11);
        test("SM4/ECB/pkcs5padding", key, 0, 32);
        testUpdate("SM4/ECB/NOPADDING", key, 0, 15);
        testUpdate("SM4/ECB/NOPADDING", key, 0, 16);
        testUpdate("SM4/ECB/NOPADDING", key, 0, 31);
        testUpdate("SM4/ECB/NOPADDING", key, 0, 32);
        testUpdate("SM4/ECB/pkcs5padding", key, 0, 15);
        testUpdate("SM4/ECB/pkcs5padding", key, 0, 16);
        testUpdate("SM4/ECB/pkcs5padding", key, 0, 31);
        testUpdate("SM4/ECB/pkcs5padding", key, 0, 32);
        testUpdateAndDofinal("SM4/ECB/NOPADDING", key, 16, 16, 7);
        testUpdateAndDofinal("SM4/ECB/NOPADDING", key, 16, 32, 32);
        testUpdateAndDofinal("SM4/ECB/pkcs5padding", key, 16, 15, 6);
        testUpdateAndDofinal("SM4/ECB/pkcs5padding", key, 16, 31, 31);
        testUpdateAndDofinal("SM4/ECB/pkcs5padding", key, 16, 16, 16);
        testUpdateAndDofinal("SM4/ECB/pkcs5padding", key, 16, 32, 18);


        testAEADMode("SM4/GCM/NOPADDING", key, 96, 1, 16);
        testAEADMode("SM4/GCM/NOPADDING", key, 104, 2, 17);
        testAEADMode("SM4/GCM/NOPADDING", key, 112, 3, 18);
        testAEADMode("SM4/GCM/NOPADDING", key, 120, 4, 19);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 5, 20);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 6, 21);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 7, 22);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 8, 23);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 9, 24);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 10, 25);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 11, 26);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 12, 27);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 13, 28);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 14, 29);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 15, 30);
        testAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 31);
        testUpdateAEADMode("SM4/GCM/NOPADDING", key, 128, 13, 15);
        testUpdateAEADMode("SM4/GCM/NOPADDING", key, 128, 14, 16);
        testUpdateAEADMode("SM4/GCM/NOPADDING", key, 128, 15, 31);
        testUpdateAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 32);
        testUpdateAndDofinalAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/GCM/NOPADDING", key, 128, 16, 32, 18);

        testAEADMode("SM4/OCB/NOPADDING", key, 64, 0, 16);
        testAEADMode("SM4/OCB/NOPADDING", key, 72, 1, 17);
        testAEADMode("SM4/OCB/NOPADDING", key, 80, 2, 18);
        testAEADMode("SM4/OCB/NOPADDING", key, 88, 3, 19);
        testAEADMode("SM4/OCB/NOPADDING", key, 96, 4, 20);
        testAEADMode("SM4/OCB/NOPADDING", key, 104, 5, 21);
        testAEADMode("SM4/OCB/NOPADDING", key, 112, 6, 22);
        testAEADMode("SM4/OCB/NOPADDING", key, 120, 7, 23);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 8, 24);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 9, 25);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 10, 26);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 11, 27);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 12, 28);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 13, 29);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 14, 30);
        testAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 31);
        testUpdateAEADMode("SM4/OCB/NOPADDING", key, 128, 12, 15);
        testUpdateAEADMode("SM4/OCB/NOPADDING", key, 128, 13, 16);
        testUpdateAEADMode("SM4/OCB/NOPADDING", key, 128, 14, 31);
        testUpdateAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 32);
        testUpdateAndDofinalAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/OCB/NOPADDING", key, 128, 15, 32, 18);


        testAEADMode("SM4/CCM/NOPADDING", key, 0, 7, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 8, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 9, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 10, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 11, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 12, 16);
        testAEADMode("SM4/CCM/NOPADDING", key, 0, 13, 16);
        testUpdateAEADMode("SM4/CCM/NOPADDING", key, 0, 10, 15);
        testUpdateAEADMode("SM4/CCM/NOPADDING", key, 0, 11, 16);
        testUpdateAEADMode("SM4/CCM/NOPADDING", key, 0, 12, 31);
        testUpdateAEADMode("SM4/CCM/NOPADDING", key, 0, 13, 32);
        testUpdateAndDofinalAEADMode("SM4/CCM/NOPADDING", key, 128, 13, 15, 6);
        testUpdateAndDofinalAEADMode("SM4/CCM/NOPADDING", key, 128, 13, 31, 31);
        testUpdateAndDofinalAEADMode("SM4/CCM/NOPADDING", key, 128, 13, 16, 16);
        testUpdateAndDofinalAEADMode("SM4/CCM/NOPADDING", key, 128, 13, 32, 18);

    }

    /**
     * test doFinal
     *
     * @param algo
     * @param key
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void test(String algo, Key key, int ivLen, int plainTextLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //test dofinal without output args
        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText, bgmPlainText);

        random.nextBytes(iv);
        ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.doFinal(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.doFinal(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);

        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }

        //generate output array
        int outputSize = bc.getOutputSize(bcCipherLen);

        byte[] bcOffsetDecrypt = new byte[20 + outputSize];
        byte[] bgmOffsetDecrypt = new byte[20 + outputSize];
        //generate outputOffset
        int offset = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcOffsetDe = bc.doFinal(bcres, ops, bcCipherLen, bcOffsetDecrypt, offset);
        int bgmOffsetDe = bgm.doFinal(bgmres, ops, bgmCipherLen, bgmOffsetDecrypt, offset);
        Assert.assertEquals(bcOffsetDe, bgmOffsetDe);
        Assert.assertArrayEquals(bcOffsetDecrypt, bgmOffsetDecrypt);
    }

    /**
     * test doFinal
     *
     * @param algo
     * @param key
     * @param tLen
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void testAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);
        GCMParameterSpec gcmParameterSpec = null;
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, iv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);

        if (!algo.contains("CCM")) {
            bc.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText, bgmPlainText);

        byte[] newIv = new byte[ivLen];
        random.nextBytes(newIv);
        while (ivLen!=0 && Arrays.equals(iv,newIv)){
            random.nextBytes(newIv);
        }

        gcmParameterSpec = new GCMParameterSpec(tLen, newIv);
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, newIv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(newIv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(newIv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.doFinal(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.doFinal(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);

        if (!algo.contains("CCM")) {
            bc.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(newIv));
            bgm.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(newIv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //generate output array
        int outputSize = bc.getOutputSize(bcCipherLen);

        byte[] bcOffsetDecrypt = new byte[20 + outputSize];
        byte[] bgmOffsetDecrypt = new byte[20 + outputSize];
        //generate outputOffset
        int offset = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcOffsetDe = bc.doFinal(bcres, ops, bcCipherLen, bcOffsetDecrypt, offset);
        int bgmOffsetDe = bgm.doFinal(bgmres, ops, bgmCipherLen, bgmOffsetDecrypt, offset);
        Assert.assertEquals(bcOffsetDe, bgmOffsetDe);
        Assert.assertArrayEquals(bcOffsetDecrypt, bgmOffsetDecrypt);
    }

    /**
     * test update
     *
     * @param algo
     * @param key
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void testUpdate(String algo, Key key, int ivLen, int plainTextLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        byte[] bcCipherText = bc.update(plainText);
        byte[] bgmCipherText = bgm.update(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);

        random.nextBytes(iv);
        ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.update(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.update(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);
    }

    /**
     * test update
     *
     * @param algo
     * @param key
     * @param tLen
     * @param ivLen
     * @param plainTextLen
     * @throws Exception
     */
    public static void testUpdateAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);
        GCMParameterSpec gcmParameterSpec = null;
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, iv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        byte[] bcCipherText = bc.update(plainText);
        byte[] bgmCipherText = bgm.update(plainText);
        Assert.assertArrayEquals(bcCipherText, bgmCipherText);

        byte[] newIv = new byte[ivLen];
        random.nextBytes(newIv);
        while (ivLen!=0 && Arrays.equals(iv,newIv)){
            random.nextBytes(newIv);
        }

        gcmParameterSpec = new GCMParameterSpec(tLen, newIv);
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, newIv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(newIv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(newIv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //test dofinal without output args
        byte[] pArr = new byte[plainTextLen + 20];
        random.nextBytes(pArr);
        int inputOffset = (int) (Math.random() * 20);

        int len = bc.getOutputSize(plainTextLen);
        byte[] bcres = new byte[len + 20];
        byte[] bgmres = new byte[len + 20];
        //generate outputOffset
        int ops = (int) (Math.random() * 20);
        //test dofinal with output args
        int bcCipherLen = bc.update(pArr, inputOffset, plainTextLen, bcres, ops);
        int bgmCipherLen = bgm.update(pArr, inputOffset, plainTextLen, bgmres, ops);
        Assert.assertEquals(bcCipherLen, bgmCipherLen);
        Assert.assertArrayEquals(bcres, bgmres);
    }

    /**
     * update is called to perform partial encryption(decryption)
     * and dofinal is called to end the encryption(decryption) process.
     *
     * @param algo
     * @param key
     * @param ivLen
     * @param plainTextLen
     * @param updateLen
     * @throws Exception
     */
    public static void testUpdateAndDofinal(String algo, Key key, int ivLen, int plainTextLen, int updateLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if (!algo.contains("ECB")) {
            bc.init(Cipher.ENCRYPT_MODE, key, ivParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key);
            bgm.init(Cipher.ENCRYPT_MODE, key);
        }
        //partial encryption
        byte[] bcUpdate = bc.update(plainText, 0, updateLen);
        byte[] bgmUpdate = bgm.update(plainText, 0, updateLen);
        Assert.assertArrayEquals(bcUpdate, bgmUpdate);
        //end the encryption
        byte[] bcdoFinalCipher = bc.doFinal(plainText, updateLen, plainTextLen - updateLen);
        byte[] bgmdoFinalCipher = bgm.doFinal(plainText, updateLen, plainTextLen - updateLen);
        Assert.assertArrayEquals(bcdoFinalCipher, bgmdoFinalCipher);
        //combine all encrypted results
        byte[] bcArr = null;
        byte[] bgmArr = null;
        if (bcUpdate == null) {
            if (bcdoFinalCipher == null) {

            } else {
                bcArr = bcdoFinalCipher;
            }
        } else {
            if (bcdoFinalCipher == null) {
                bcArr = bcUpdate;
            } else {
                bcArr = new byte[bcUpdate.length + bcdoFinalCipher.length];
                SM4Util.copyArray(bcUpdate, 0, bcUpdate.length, bcArr, 0);
                SM4Util.copyArray(bcdoFinalCipher, 0, bcdoFinalCipher.length, bcArr, bcArr.length - bcdoFinalCipher.length);
            }
        }

        if (bgmUpdate == null) {
            if (bgmdoFinalCipher == null) {
            } else {
                bgmArr = bgmdoFinalCipher;
            }
        } else {
            if (bgmdoFinalCipher == null) {
                bgmArr = bgmUpdate;
            } else {
                bgmArr = new byte[bgmUpdate.length + bgmdoFinalCipher.length];
                SM4Util.copyArray(bgmUpdate, 0, bgmUpdate.length, bgmArr, 0);
                SM4Util.copyArray(bgmdoFinalCipher, 0, bgmdoFinalCipher.length, bgmArr, bgmArr.length - bgmdoFinalCipher.length);
            }
        }
        Assert.assertArrayEquals(bcArr, bgmArr);

        if (!algo.contains("ECB")) {
            bc.init(Cipher.DECRYPT_MODE, key, ivParam);
            bgm.init(Cipher.DECRYPT_MODE, key, ivParam);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key);
            bgm.init(Cipher.DECRYPT_MODE, key);
        }
        int decryptLen = (int) (Math.random() * bcArr.length);
        //partial decryption
        byte[] deBCupdate = bc.update(bcArr, 0, decryptLen);
        byte[] deBgmUpdate = bgm.update(bgmArr, 0, decryptLen);
        Assert.assertArrayEquals(deBCupdate, deBgmUpdate);
        //end the decryption
        byte[] bcbytes = bc.doFinal(bcArr, decryptLen, bcArr.length - decryptLen);
        byte[] bgmbytes = bgm.doFinal(bgmArr, decryptLen, bgmArr.length - decryptLen);
        Assert.assertArrayEquals(bcbytes, bgmbytes);
    }

    /**
     * update is called to perform partial encryption(decryption)
     * and dofinal is called to end the encryption(decryption) process.
     *
     * @param algo
     * @param key
     * @param tLen
     * @param ivLen
     * @param plainTextLen
     * @param updateLen
     */
    public static void testUpdateAndDofinalAEADMode(String algo, Key key, int tLen, int ivLen, int plainTextLen, int updateLen) throws Exception {
        Cipher bc = Cipher.getInstance(algo, "BC");
        Cipher bgm = Cipher.getInstance(algo, "BGMJCEProvider");

        //generate iv and tagLen
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);
        GCMParameterSpec gcmParameterSpec = null;
        if (!algo.contains("CCM")) {
            gcmParameterSpec = new GCMParameterSpec(tLen, iv);
            bc.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        //generate plainText
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);


        //generate additional authentication data

        //partial encryption
        byte[] bcUpdate = bc.update(plainText, 0, updateLen);
        byte[] bgmUpdate = bgm.update(plainText, 0, updateLen);
        Assert.assertArrayEquals(bcUpdate, bgmUpdate);

        //end the encryption
        byte[] bcdoFinalCipher = bc.doFinal(plainText, updateLen, plainTextLen - updateLen);
        byte[] bgmdoFinalCipher = bgm.doFinal(plainText, updateLen, plainTextLen - updateLen);
        Assert.assertArrayEquals(bcdoFinalCipher, bgmdoFinalCipher);

        //combine all encrypted results
        byte[] bcArr = null;
        byte[] bgmArr = null;

        if (bcUpdate == null) {
            if (bcdoFinalCipher == null) {

            } else {
                bcArr = bcdoFinalCipher;
            }
        } else {
            if (bcdoFinalCipher == null) {
                bcArr = bcUpdate;
            } else {
                bcArr = new byte[bcUpdate.length + bcdoFinalCipher.length];
                SM4Util.copyArray(bcUpdate, 0, bcUpdate.length, bcArr, 0);
                SM4Util.copyArray(bcdoFinalCipher, 0, bcdoFinalCipher.length, bcArr, bcArr.length - bcdoFinalCipher.length);
            }
        }

        if (bgmUpdate == null) {
            if (bgmdoFinalCipher == null) {
            } else {
                bgmArr = bgmdoFinalCipher;
            }
        } else {
            if (bgmdoFinalCipher == null) {
                bgmArr = bgmUpdate;
            } else {
                bgmArr = new byte[bgmUpdate.length + bgmdoFinalCipher.length];
                SM4Util.copyArray(bgmUpdate, 0, bgmUpdate.length, bgmArr, 0);
                SM4Util.copyArray(bgmdoFinalCipher, 0, bgmdoFinalCipher.length, bgmArr, bgmArr.length - bgmdoFinalCipher.length);
            }
        }
        Assert.assertArrayEquals(bcArr, bgmArr);


        if (!algo.contains("CCM")) {
            bc.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        } else {
            bc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            bgm.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);

        //partial decryption
        int decryptLen = (int) (Math.random() * bcArr.length);
        byte[] deBCupdate = bc.update(bcArr, 0, decryptLen);
        byte[] deBgmUpdate = bgm.update(bgmArr, 0, decryptLen);
        Assert.assertArrayEquals(deBCupdate, deBgmUpdate);
        //end the decryption
        byte[] bcbytes = bc.doFinal(bcArr, decryptLen, bcArr.length - decryptLen);
        byte[] bgmbytes = bgm.doFinal(bgmArr, decryptLen, bgmArr.length - decryptLen);
        Assert.assertArrayEquals(bcbytes, bgmbytes);
    }
}
