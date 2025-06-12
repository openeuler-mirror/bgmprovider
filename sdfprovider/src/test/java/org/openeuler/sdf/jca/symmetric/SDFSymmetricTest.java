package org.openeuler.sdf.jca.symmetric;

import org.junit.Assert;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.util.SDFKeyTestDB;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SDFSymmetricTest extends SDFTestCase {
    private static final Provider sdf = new SDFProvider();
    private static final Provider bgm = new BGMJCEProvider();

    protected void testEncryptBaseLine(String algorithm, int blockSize, SDFKeyTestDB key, int ivLen) throws Exception {
        byte[] data;
        int splitOffset;

        String transformation = algorithm + "/ECB/NoPadding";

        data = new byte[13456];
        splitOffset = 2989;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = new byte[0];
        splitOffset = 0;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = SDFTestUtil.generateRandomBytes(368);
        splitOffset = 41;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = SDFTestUtil.generateRandomBytes(blockSize * SDFTestUtil.generateRandomInt());
        splitOffset = SDFTestUtil.generateRandomInt(data.length);
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        transformation = algorithm + "/ECB/PKCS5Padding";
        data = new byte[0];
        splitOffset = 0;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = new byte[1021];
        Arrays.fill(data, (byte) 1);
        splitOffset = 80;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = SDFTestUtil.generateRandomBytes(368);
        splitOffset = 41;
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        data = SDFTestUtil.generateRandomBytes();
        splitOffset = SDFTestUtil.generateRandomInt(data.length);
        testEncryptBaseLine(transformation, key, data, splitOffset, null);

        byte[] ivBytes = SDFTestUtil.generateRandomBytes(ivLen);
        transformation = algorithm + "/CBC/NoPadding";
        data = new byte[0];
        splitOffset = 0;
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        data = SDFTestUtil.generateRandomBytes(368);
        splitOffset = 41;
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        data = SDFTestUtil.generateRandomBytes(blockSize * SDFTestUtil.generateRandomInt());
        splitOffset = SDFTestUtil.generateRandomInt(data.length);
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        transformation = algorithm + "/CBC/PKCS5Padding";
        data = new byte[0];
        splitOffset = 0;
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        data = new byte[29];
        splitOffset = 25;
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        data = SDFTestUtil.generateRandomBytes(368);
        splitOffset = 41;
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);

        data = SDFTestUtil.generateRandomBytes();
        splitOffset = SDFTestUtil.generateRandomInt(data.length);
        testEncryptBaseLine(transformation, key, data, splitOffset, ivBytes);
    }

    protected void testECB(String algorithm, int blockSize, int keySize) throws Exception {
        SecretKey secretKey = SDFSymmetricTestUtil.generateKey(algorithm, sdf, keySize, true);
        System.out.println("secretKey=" + new String(secretKey.getEncoded()));

        String transformation = algorithm + "/ECB/NoPadding";
        // test empty bytes
        test(transformation, secretKey, new byte[0], null);
        // test 1 blocksize bytes
        test(transformation, secretKey, SDFTestUtil.generateRandomBytes(blockSize), null);
        // test randomly
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytes(blockSize * SDFTestUtil.generateRandomInt()), null);

        transformation = algorithm + "/ECB/PKCS5Padding";
        // test empty bytes
        test(transformation, secretKey,
                new byte[0], null);
        // test 15 bytes
        test(transformation, secretKey,
                new byte[15], null);
        // test 31 bytes
        test(transformation, secretKey,
                new byte[31], null);

        test(transformation, secretKey, SDFTestUtil.generateRandomBytes(blockSize), null);

        // test bytes less than BLOCK_SIZE
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytesByBound(blockSize), null);
        test(transformation, secretKey, SDFTestUtil.generateRandomBytes(blockSize), null);
        // test randomly
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytes(), null);
    }

    protected void testCBC(String algorithm, int blockSize, int keySize, int ivLen) throws Exception {
        SecretKey secretKey = SDFSymmetricTestUtil.generateKey(algorithm, sdf, keySize, true);
        byte[] ivBytes = SDFTestUtil.generateRandomBytes(ivLen);

        String transformation = algorithm + "/CBC/NoPadding";
        test(transformation, secretKey, new byte[0], ivBytes);
        test(transformation, secretKey, SDFTestUtil.generateRandomBytes(blockSize), ivBytes);
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytes(blockSize * SDFTestUtil.generateRandomInt()), ivBytes);

        transformation = algorithm + "/CBC/PKCS5Padding";
        test(transformation, secretKey, new byte[0], ivBytes);
        test(transformation, secretKey, SDFTestUtil.generateRandomBytes(blockSize), ivBytes);
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytesByBound(blockSize), ivBytes);
        test(transformation, secretKey,
                SDFTestUtil.generateRandomBytes(), ivBytes);
    }

    private static void test(String algorithm, SecretKey secretKey, byte[] data, byte[] ivBytes) throws Exception {
        System.out.println("----------------------------------------------------------");
        System.out.println("algorithm=" + algorithm);
        System.out.println("secretKey=" + Arrays.toString(secretKey.getEncoded()));
        System.out.println("data.length= " + data.length + ", data=" + Arrays.toString(data));
        if (ivBytes != null) {
            System.out.println("ivBytes.length= " + ivBytes.length + ", ivBytes=" + Arrays.toString(ivBytes));
        }
        AlgorithmParameterSpec spec = null;
        if (ivBytes != null) {
            spec = new IvParameterSpec(ivBytes);
        }
        byte[] encData;
        byte[] decData;

        System.out.println("case 1: test doFinal");
        encData = SDFSymmetricTestUtil.encryptDoFinal(algorithm, sdf, secretKey, spec, data);
        decData = SDFSymmetricTestUtil.decryptDoFinal(algorithm, sdf, secretKey, spec, encData);
        System.out.println("case 1 encData.length= " + encData.length + " encData=" + Arrays.toString(encData));
        System.out.println("case 1 decData.length= " + decData.length + " decData=" + Arrays.toString(decData));
        Assert.assertArrayEquals("test case 1 failed", data, decData);

        System.out.println("case 2: test update and doFinal");
        encData = SDFSymmetricTestUtil.encryptUpdateAndDoFinal(algorithm, sdf, secretKey, spec, data);
        decData = SDFSymmetricTestUtil.decryptUpdateAndDoFinal(algorithm, sdf, secretKey, spec, encData);
        System.out.println("case 2 encData.length= " + encData.length + " encData=" + Arrays.toString(encData));
        System.out.println("case 2 decData.length= " + decData.length + " decData=" + Arrays.toString(decData));
        Assert.assertArrayEquals("test case 2 failed", data, decData);
        System.out.println("----------------------------------------------------------");
    }

    private static void testEncryptBaseLine(String algorithm, SDFKeyTestDB keyDB, byte[] data, int splitOffset,
                                            byte[] ivBytes)
            throws Exception {
        SecretKey encKey = new SDFSecretKeySpec(keyDB.getEncKey(), keyDB.getAlgorithm(), true);
        SecretKey plainKey = new SecretKeySpec(keyDB.getPlainKey(), keyDB.getAlgorithm());
        System.out.println("----------------------------------------------------------");
        System.out.println("algorithm=" + algorithm);
        System.out.println("encKey=" + Arrays.toString(encKey.getEncoded()));
        System.out.println("plainKey=" + Arrays.toString(plainKey.getEncoded()));
        System.out.println("data.length= " + data.length + ", data=" + Arrays.toString(data));
        testUpdateBaseLine(algorithm, encKey, plainKey, data, splitOffset, ivBytes);
        testDoFinalBaseLine(algorithm, encKey, plainKey, data, splitOffset, ivBytes);
        testUpdateAndDoFinalBaseLine(algorithm, encKey, plainKey, data, splitOffset, ivBytes);
        System.out.println("----------------------------------------------------------");
    }

    private static void testUpdateBaseLine(String algorithm, SecretKey encKey, SecretKey plainKey, byte[] data,
                                           int splitOffset, byte[] ivBytes) throws Exception {
        ByteArrayOutputStream bgmOut = new ByteArrayOutputStream();
        byte[] bgmEncAllData;
        byte[] bgmDecAllData;
        byte[] bgmEncData;
        byte[] bgmDecData;

        ByteArrayOutputStream sdfOut = new ByteArrayOutputStream();
        byte[] sdfEncAllData;
        byte[] sdfDecAllData;
        byte[] sdfEncData;
        byte[] sdfDecData;

        AlgorithmParameterSpec spec = null;
        if (ivBytes != null) {
            spec = new IvParameterSpec(ivBytes);
        }

        System.out.println("case 1-1: baseline -- test encrypt update");
        Cipher bgmCipher = Cipher.getInstance(algorithm, bgm);
        bgmCipher.init(Cipher.ENCRYPT_MODE, plainKey, spec);
        Cipher sdfCipher = Cipher.getInstance(algorithm, sdf);
        sdfCipher.init(Cipher.ENCRYPT_MODE, encKey, spec);

        int off = 0;
        int len = splitOffset;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmEncData = bgmCipher.update(data, off, len);
        if (bgmEncData != null) {
            bgmOut.write(bgmEncData);
        }
        sdfEncData = sdfCipher.update(data, off, len);
        if (sdfEncData != null) {
            sdfOut.write(sdfEncData);
        }
        System.out.println("bgmEncData=" + Arrays.toString(bgmEncData));
        System.out.println("sdfEncData=" + Arrays.toString(sdfEncData));
        Assert.assertArrayEquals("test case 1-1 update phase 1 failed", bgmEncData, sdfEncData);

        off += len;
        len = data.length - off;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmEncData = bgmCipher.update(data, off, len);
        if (bgmEncData != null) {
            bgmOut.write(bgmEncData);
        }
        sdfEncData = sdfCipher.update(data, off, len);
        if (sdfEncData != null) {
            sdfOut.write(sdfEncData);
        }
        System.out.println("bgmEncData=" + Arrays.toString(bgmEncData));
        System.out.println("sdfEncData=" + Arrays.toString(sdfEncData));
        Assert.assertArrayEquals("test case 1-1 update phase 2 failed", bgmEncData, sdfEncData);

        bgmEncData = bgmCipher.doFinal();
        if (bgmEncData != null) {
            bgmOut.write(bgmEncData);
        }
        sdfEncData = sdfCipher.doFinal();
        if (sdfEncData != null) {
            sdfOut.write(sdfEncData);
        }
        System.out.println("bgmEncData=" + Arrays.toString(bgmEncData));
        System.out.println("sdfEncData=" + Arrays.toString(sdfEncData));
        Assert.assertArrayEquals("test case 1-1 doFinal phase 3 failed", bgmEncData, sdfEncData);

        System.out.println("case 1-2: baseline -- test decrypt update");
        bgmEncAllData = bgmOut.toByteArray();
        bgmOut.reset();

        sdfEncAllData = sdfOut.toByteArray();
        sdfOut.reset();

        bgmCipher.init(Cipher.DECRYPT_MODE, plainKey, spec);
        sdfCipher.init(Cipher.DECRYPT_MODE, encKey, spec);

        bgmDecData = bgmCipher.doFinal(bgmEncAllData);

        sdfDecData = sdfCipher.doFinal(sdfEncAllData);
        System.out.println("bgmDecData=" + Arrays.toString(bgmDecData));
        System.out.println("sdfDecData=" + Arrays.toString(sdfDecData));
        Assert.assertArrayEquals("test failed", bgmDecData, sdfDecData);

        off = 0;
        len = splitOffset;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmDecData = bgmCipher.update(sdfEncAllData, off, len);
        if (bgmDecData != null) {
            bgmOut.write(bgmDecData);
        }
        sdfDecData = sdfCipher.update(sdfEncAllData, off, len);
        if (sdfDecData != null) {
            sdfOut.write(sdfDecData);
        }
        System.out.println("bgmDecData=" + Arrays.toString(bgmDecData));
        System.out.println("sdfDecData=" + Arrays.toString(sdfDecData));
        Assert.assertArrayEquals("test case 1-2 update phase 1 failed", bgmDecData, sdfDecData);

        off += len;
        len = sdfEncAllData.length - off;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmDecData = bgmCipher.update(sdfEncAllData, off, len);
        if (bgmDecData != null) {
            bgmOut.write(bgmDecData);
        }
        sdfDecData = sdfCipher.update(sdfEncAllData, off, len);
        if (sdfDecData != null) {
            sdfOut.write(sdfDecData);
        }
        System.out.println("bgmDecData=" + Arrays.toString(bgmDecData));
        System.out.println("sdfDecData=" + Arrays.toString(sdfDecData));
        Assert.assertArrayEquals("test case 1-2 update phase 2 failed", bgmDecData, sdfDecData);

        bgmDecData = bgmCipher.doFinal();
        if (bgmDecData != null) {
            bgmOut.write(bgmDecData);
        }
        sdfDecData = sdfCipher.doFinal();
        if (sdfDecData != null) {
            sdfOut.write(sdfDecData);
        }
        Assert.assertArrayEquals("test case 1-2 doFinal phase 3 failed", bgmDecData, sdfDecData);

        bgmDecAllData = bgmOut.toByteArray();
        sdfDecAllData = sdfOut.toByteArray();
        Assert.assertArrayEquals(bgmDecAllData, sdfDecAllData);
        Assert.assertArrayEquals(data, sdfDecAllData);
    }

    private static void testDoFinalBaseLine(String algorithm, SecretKey encKey, SecretKey plainKey, byte[] data,
                                            int splitOffset, byte[] ivBytes) throws Exception {
        AlgorithmParameterSpec spec = null;
        if (ivBytes != null) {
            spec = new IvParameterSpec(ivBytes);
        }
        Cipher bgmCipher = Cipher.getInstance(algorithm, bgm);
        bgmCipher.init(Cipher.ENCRYPT_MODE, plainKey, spec);
        Cipher sdfCipher = Cipher.getInstance(algorithm, sdf);
        sdfCipher.init(Cipher.ENCRYPT_MODE, encKey, spec);

        byte[] bgmEncData;
        byte[] bgmDecData;

        byte[] sdfEncData;
        byte[] sdfDecData;

        System.out.println("case 2-1: baseline -- test encrypt doFinal");
        int off = 0;
        int len = data.length;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmEncData = bgmCipher.doFinal(data, off, len);
        sdfEncData = sdfCipher.doFinal(data, off, len);
        System.out.println("bgmEncData=" + Arrays.toString(bgmEncData));
        System.out.println("sdfEncData=" + Arrays.toString(sdfEncData));
        Assert.assertArrayEquals("test case  2-1 encrypt doFinal failed", bgmEncData, sdfEncData);

        System.out.println("case 2-2: baseline -- test decrypt doFinal");
        bgmCipher.init(Cipher.DECRYPT_MODE, plainKey, spec);
        sdfCipher.init(Cipher.DECRYPT_MODE, encKey, spec);
        bgmDecData = bgmCipher.doFinal(bgmEncData);
        sdfDecData = sdfCipher.doFinal(sdfEncData);

        Assert.assertArrayEquals("test case 2-2 decrypt doFinal failed", bgmDecData, sdfDecData);

        Assert.assertArrayEquals(data, sdfDecData);

    }

    private static void testUpdateAndDoFinalBaseLine(String algorithm, SecretKey encKey, SecretKey plainKey,
                                                     byte[] data, int splitOffset, byte[] ivBytes) throws Exception {
        AlgorithmParameterSpec spec = null;
        if (ivBytes != null) {
            spec = new IvParameterSpec(ivBytes);
        }
        Cipher bgmCipher = Cipher.getInstance(algorithm, bgm);
        bgmCipher.init(Cipher.ENCRYPT_MODE, plainKey, spec);
        Cipher sdfCipher = Cipher.getInstance(algorithm, sdf);
        sdfCipher.init(Cipher.ENCRYPT_MODE, encKey, spec);

        ByteArrayOutputStream bgmOut = new ByteArrayOutputStream();
        byte[] bgmEncAllData;
        byte[] bgmDecAllData;
        byte[] bgmEncData;
        byte[] bgmDecData;

        ByteArrayOutputStream sdfOut = new ByteArrayOutputStream();
        byte[] sdfEncAllData;
        byte[] sdfDecAllData;
        byte[] sdfEncData;
        byte[] sdfDecData;

        System.out.println("case 3-1: baseline -- test encrypt update and doFinal");
        int off = 0;
        int len = splitOffset;
        System.out.println("off=" + off);
        System.out.println("len=" + len);
        bgmEncData = bgmCipher.update(data, off, len);
        if (bgmEncData != null) {
            bgmOut.write(bgmEncData);
        }
        sdfEncData = sdfCipher.update(data, off, len);
        if (sdfEncData != null) {
            sdfOut.write(sdfEncData);
        }
        Assert.assertArrayEquals("test case 3-1 encrypt update failed", bgmEncData, sdfEncData);

        off += len;
        len = data.length - off;
        bgmEncData = bgmCipher.doFinal(data, off, len);
        if (bgmEncData != null) {
            bgmOut.write(bgmEncData);
        }
        sdfEncData = sdfCipher.doFinal(data, off, len);
        if (sdfEncData != null) {
            sdfOut.write(sdfEncData);
        }
        Assert.assertArrayEquals("test case 3-1 encrypt doFinal failed", bgmEncData, sdfEncData);
        System.out.println("----------------------------------------------------------");

        System.out.println("case 3-2: baseline -- test decrypt update and doFinal");
        bgmEncAllData = bgmOut.toByteArray();
        bgmOut.reset();

        sdfEncAllData = sdfOut.toByteArray();
        sdfOut.reset();

        bgmCipher.init(Cipher.DECRYPT_MODE, plainKey, spec);
        sdfCipher.init(Cipher.DECRYPT_MODE, encKey, spec);

        off = 0;
        len = splitOffset;
        bgmDecData = bgmCipher.update(bgmEncAllData, off, len);
        if (bgmDecData != null) {
            bgmOut.write(bgmDecData);
        }
        sdfDecData = sdfCipher.update(sdfEncAllData, off, len);
        if (sdfDecData != null) {
            sdfOut.write(sdfDecData);
        }
        Assert.assertArrayEquals("test case 3-2 decrypt update failed", bgmDecData, sdfDecData);

        off = splitOffset;
        len = bgmEncAllData.length - off;
        bgmDecData = bgmCipher.doFinal(bgmEncAllData, off, len);
        if (bgmDecData != null) {
            bgmOut.write(bgmDecData);
        }
        sdfDecData = sdfCipher.doFinal(sdfEncAllData, off, len);
        if (sdfDecData != null) {
            sdfOut.write(sdfDecData);
        }
        Assert.assertArrayEquals("test case 3-2 decrypt doFinal failed", bgmDecData, sdfDecData);

        bgmDecAllData = bgmOut.toByteArray();
        sdfDecAllData = sdfOut.toByteArray();
        Assert.assertArrayEquals(bgmDecAllData, sdfDecAllData);
        Assert.assertArrayEquals(data, sdfDecAllData);
    }
}
