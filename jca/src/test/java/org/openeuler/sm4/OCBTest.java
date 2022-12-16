package org.openeuler.sm4;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * test for OCB
 */
public class OCBTest {

    //Valid authentication tag length
    private int[] tLenArr = new int[]{128, 120, 112, 104, 96, 88, 80, 72, 64};

    @Before
    public void installProvider() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    @Test
    public void testOCB() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(16);
        SecretKey key = keyGen.generateKey();

        Cipher bcNopaddingCipher = Cipher.getInstance("SM4/OCB/NOPADDING", "BC");
        Cipher bgmNopaddingCipher = Cipher.getInstance("SM4/OCB/NOPADDING", "BGMJCEProvider");

        testUpdate(bcNopaddingCipher, bgmNopaddingCipher, key);
        testUpdateAndDofinal(bcNopaddingCipher, bgmNopaddingCipher, key);
        testNoPadding(bcNopaddingCipher, bgmNopaddingCipher, key);
        testAAd(bcNopaddingCipher, bgmNopaddingCipher, key);
    }

    /**
     * Encryption and decryption tests
     * for OCB only no padding is supported
     *
     * @param bc
     * @param bgm
     * @param key
     * @throws Exception
     */
    private void testNoPadding(Cipher bc, Cipher bgm, SecretKey key) throws Exception {
        int times = 1000;
        for (int i = 0; i < times; i++) {
            //generate the length of iv and authentication tag  randomly
            int ivLen = (int) (Math.random() * 16);
            byte[] iv = new byte[ivLen];
            new SecureRandom().nextBytes(iv);
            int tLenArrIndex = (int) (Math.random() * tLenArr.length);
            GCMParameterSpec gcmParam = new GCMParameterSpec(tLenArr[tLenArrIndex], iv);
            //generate plainText randomly
            //bouncycastle:Number of bits per request limited to 262144
            int plainTextLen = (((int) (Math.random() * 32767)) + 1);
            byte[] noPaddingPlainText = new byte[plainTextLen];
            SecureRandom random = new SecureRandom();
            random.nextBytes(noPaddingPlainText);

            bc.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            byte[] clone = noPaddingPlainText.clone();
            //test dofinal without output args
            byte[] bcdoFinal = bc.doFinal(noPaddingPlainText);
            byte[] bgmdoFinal = bgm.doFinal(clone);
            Assert.assertArrayEquals(bcdoFinal, bgmdoFinal);


            bc.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParam);
            //generate output array
            int outputSize = bc.getOutputSize(bcdoFinal.length);
            int size = (int) (Math.random() * 20);
            byte[] bcOffsetDecrypt = new byte[size + outputSize];
            byte[] bgmOffsetDecrypt = new byte[size + outputSize];
            //generate outputOffset randomly
            int offset = (int) (Math.random() * size);
            //test dofinal with output args
            int bcOffsetDe = bc.doFinal(bcdoFinal, 0, bcdoFinal.length, bcOffsetDecrypt, offset);
            int bgmOffsetDe = bgm.doFinal(bgmdoFinal, 0, bgmdoFinal.length, bgmOffsetDecrypt, offset);
            Assert.assertEquals(bcOffsetDe, bgmOffsetDe);
            Assert.assertArrayEquals(bcOffsetDecrypt, bgmOffsetDecrypt);

            bc.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            //test dofinal with output args
            int len = bc.getOutputSize(bcOffsetDe);
            size = (int) (Math.random() * 20);
            byte[] bcres = new byte[len + size];
            byte[] bgmres = new byte[len + size];
            //generate outputOffset randomly
            int ops = (int) (Math.random() * size);
            int bcCipherLen = bc.doFinal(bcOffsetDecrypt, offset, bcOffsetDe, bcres, ops);
            int bgmCipherLen = bgm.doFinal(bgmOffsetDecrypt, offset, bgmOffsetDe, bgmres, ops);
            Assert.assertEquals(bcCipherLen, bgmCipherLen);
            Assert.assertArrayEquals(bcres, bgmres);

            //test dofinal without output args
            bc.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParam);
            byte[] bcbytes = bc.doFinal(bcres, ops, bcCipherLen);
            byte[] bgmbytes = bgm.doFinal(bgmres, ops, bgmCipherLen);
            Assert.assertArrayEquals(bcbytes, bgmbytes);
        }
    }

    /**
     * test update method
     *
     * @param bc
     * @param bgm
     * @param key
     * @throws Exception
     */
    private void testUpdate(Cipher bc, Cipher bgm, SecretKey key) throws Exception {
        int times = 1000;
        for (int i = 0; i < times; i++) {
            //generate the length of iv and authentication tag  randomly
            int ivLen = (int) (Math.random() * 16);
            byte[] iv = new byte[ivLen];
            new SecureRandom().nextBytes(iv);
            int tLenArrIndex = (int) (Math.random() * tLenArr.length);
            GCMParameterSpec gcmParam = new GCMParameterSpec(tLenArr[tLenArrIndex], iv);
            //generate plainText randomly
            int plainTextLen = (((int) (Math.random() * 32767)) + 1);
            byte[] noPaddingPlainText = new byte[plainTextLen];
            SecureRandom random = new SecureRandom();
            random.nextBytes(noPaddingPlainText);

            bc.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            byte[] clone = noPaddingPlainText.clone();
            byte[] bcUpdate = bc.update(noPaddingPlainText);
            byte[] bgmUpdate = bgm.update(clone);

            Assert.assertArrayEquals(bcUpdate, bgmUpdate);

            byte[] bcFinal_en = bc.doFinal();
            byte[] bgmFinal_en = bgm.doFinal();
        }
    }

    /**
     * update is called to perform partial encryption(decryption)
     * and dofinal is called to end the encryption(decryption) process.
     *
     * @param bc
     * @param bgm
     * @param key
     * @throws Exception
     */
    private void testUpdateAndDofinal(Cipher bc, Cipher bgm, SecretKey key) throws Exception {
        int times = 10000;
        for (int i = 0; i < times; i++) {
            //generate plainText
            int plainTextLen;
            plainTextLen = (((int) (Math.random() * 32767)) + 1);
            byte[] plainText = new byte[plainTextLen];
            SecureRandom random = new SecureRandom();
            random.nextBytes(plainText);
            //generate iv and tagLen
            int ivLen = (int) (Math.random() * 16);
            byte[] iv = new byte[ivLen];
            new SecureRandom().nextBytes(iv);
            int tLenArrIndex = (int) (Math.random() * tLenArr.length);
            GCMParameterSpec gcmParam = new GCMParameterSpec(tLenArr[tLenArrIndex], iv);
            //generate additional authentication data
            int aadLen = (((int) (Math.random() * 32767)) + 1);
            byte[] aad = new byte[aadLen];
            random.nextBytes(aad);

            bc.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bc.updateAAD(aad);
            bgm.updateAAD(aad);

            //partial encryption
            byte[] clone = plainText.clone();
            int updateLen = (int) (Math.random() * plainTextLen);
            byte[] bcUpdate = bc.update(plainText, 0, updateLen);
            byte[] bgmUpdate = bgm.update(clone, 0, updateLen);
            Assert.assertArrayEquals(bcUpdate, bgmUpdate);

            //end the encryption
            byte[] bcdoFinalCipher = bc.doFinal(plainText, updateLen, plainTextLen - updateLen);
            byte[] bgmdoFinalCipher = bgm.doFinal(clone, updateLen, plainTextLen - updateLen);
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

            //partial decryption
            bc.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bc.updateAAD(aad);
            bgm.updateAAD(aad);
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

    /**
     * test encryption(decryption) with additional authentication data
     *
     * @param bc
     * @param bgm
     * @param key
     * @throws Exception
     */
    private void testAAd(Cipher bc, Cipher bgm, SecretKey key) throws Exception {
        int times = 1000;
        for (int i = 0; i < times; i++) {
            //generate plainText
            int plainTextLen;
            plainTextLen = (((int) (Math.random() * 32767)) + 1);
            byte[] plainText = new byte[plainTextLen];
            SecureRandom random = new SecureRandom();
            random.nextBytes(plainText);
            //generate iv and tagLen
            int ivLen = (int) (Math.random() * 16);
            byte[] iv = new byte[ivLen];
            new SecureRandom().nextBytes(iv);
            int tLenArrIndex = (int) (Math.random() * tLenArr.length);
            GCMParameterSpec gcmParam = new GCMParameterSpec(tLenArr[tLenArrIndex], iv);
            //generate  additional authentication data
            int aadLen = (((int) (Math.random() * 32767)) + 1);
            byte[] aad = new byte[aadLen];
            random.nextBytes(aad);

            bc.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.ENCRYPT_MODE, key, gcmParam);
            bc.updateAAD(aad);
            bgm.updateAAD(aad);
            byte[] bcEn = bc.doFinal(plainText);
            byte[] bgmEn = bgm.doFinal(plainText);
            Assert.assertArrayEquals(bcEn, bgmEn);

            bc.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bgm.init(Cipher.DECRYPT_MODE, key, gcmParam);
            bc.updateAAD(aad);
            bgm.updateAAD(aad);
            byte[] bcDe = bc.doFinal(bcEn);
            byte[] bgmDe = bgm.doFinal(bgmEn);
            Assert.assertArrayEquals(bcDe, bgmDe);
        }
    }

}