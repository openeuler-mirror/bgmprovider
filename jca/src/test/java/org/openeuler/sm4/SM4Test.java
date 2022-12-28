package org.openeuler.sm4;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.openeuler.BGMJCEProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * SM4 full test
 */
public class SM4Test {

    public static void installProvider() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    public static void main(String[] args)  throws Exception{
        installProvider();
        test();
    }


    public static void test() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        keyGen.init(16);
        SecretKey key = keyGen.generateKey();

        test("SM4/CBC/NOPADDING",key,16,64);
        test("SM4/CBC/pkcs5padding",key,16,11);
        test("SM4/CBC/pkcs5padding",key,16,32);

        test("SM4/CFB/NOPADDING",key,16,128);
        test("SM4/CFB/pkcs5padding",key,16,22);
        test("SM4/CFB/pkcs5padding",key,16,32);

        test("SM4/CTS/NOPADDING",key,16,32);
        test("SM4/CTS/NOPADDING",key,16,33);
        test("SM4/CTS/pkcs5padding",key,16,11);
        test("SM4/CTS/pkcs5padding",key,16,32);

        test("SM4/CTR/NOPADDING",key,8,11);
        test("SM4/CTR/NOPADDING",key,9,13);
        test("SM4/CTR/NOPADDING",key,10,7);
        test("SM4/CTR/NOPADDING",key,11,19);
        test("SM4/CTR/NOPADDING",key,12,21);
        test("SM4/CTR/NOPADDING",key,13,11);
        test("SM4/CTR/NOPADDING",key,14,12);
        test("SM4/CTR/NOPADDING",key,15,14);
        test("SM4/CTR/NOPADDING",key,16,15);
        test("SM4/CTR/pkcs5padding",key,16,15);
        test("SM4/CTR/pkcs5padding",key,16,16);

        test("SM4/OFB/NOPADDING",key,16,32);
        test("SM4/OFB/pkcs5padding",key,16,15);
        test("SM4/OFB/pkcs5padding",key,16,32);

        test("SM4/ECB/NOPADDING",key,0,16);
        test("SM4/ECB/pkcs5padding",key,0,11);
        test("SM4/ECB/pkcs5padding",key,0,32);

        testAEADMode("SM4/GCM/NOPADDING",key,96,1,16);
        testAEADMode("SM4/GCM/NOPADDING",key,104,2,17);
        testAEADMode("SM4/GCM/NOPADDING",key,112,3,18);
        testAEADMode("SM4/GCM/NOPADDING",key,120,4,19);
        testAEADMode("SM4/GCM/NOPADDING",key,128,5,20);
        testAEADMode("SM4/GCM/NOPADDING",key,128,6,21);
        testAEADMode("SM4/GCM/NOPADDING",key,128,7,22);
        testAEADMode("SM4/GCM/NOPADDING",key,128,8,23);
        testAEADMode("SM4/GCM/NOPADDING",key,128,9,24);
        testAEADMode("SM4/GCM/NOPADDING",key,128,10,25);
        testAEADMode("SM4/GCM/NOPADDING",key,128,11,26);
        testAEADMode("SM4/GCM/NOPADDING",key,128,12,27);
        testAEADMode("SM4/GCM/NOPADDING",key,128,13,28);
        testAEADMode("SM4/GCM/NOPADDING",key,128,14,29);
        testAEADMode("SM4/GCM/NOPADDING",key,128,15,30);
        testAEADMode("SM4/GCM/NOPADDING",key,128,16,31);

        testAEADMode("SM4/OCB/NOPADDING",key,64,0,16);
        testAEADMode("SM4/OCB/NOPADDING",key,72,1,17);
        testAEADMode("SM4/OCB/NOPADDING",key,80,2,18);
        testAEADMode("SM4/OCB/NOPADDING",key,88,3,19);
        testAEADMode("SM4/OCB/NOPADDING",key,96,4,20);
        testAEADMode("SM4/OCB/NOPADDING",key,104,5,21);
        testAEADMode("SM4/OCB/NOPADDING",key,112,6,22);
        testAEADMode("SM4/OCB/NOPADDING",key,120,7,23);
        testAEADMode("SM4/OCB/NOPADDING",key,128,8,24);
        testAEADMode("SM4/OCB/NOPADDING",key,128,9,25);
        testAEADMode("SM4/OCB/NOPADDING",key,128,10,26);
        testAEADMode("SM4/OCB/NOPADDING",key,128,11,27);
        testAEADMode("SM4/OCB/NOPADDING",key,128,12,28);
        testAEADMode("SM4/OCB/NOPADDING",key,128,13,29);
        testAEADMode("SM4/OCB/NOPADDING",key,128,14,30);
        testAEADMode("SM4/OCB/NOPADDING",key,128,15,31);

        testAEADMode("SM4/CCM/NOPADDING",key,0,7,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,8,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,9,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,10,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,11,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,12,16);
        testAEADMode("SM4/CCM/NOPADDING",key,0,13,16);
    }
    public static void test(String algo,Key key,int ivLen, int plainTextLen) throws Exception{
        Cipher bc = Cipher.getInstance(algo,"BC");
        Cipher bgm = Cipher.getInstance(algo,"BGMJCEProvider");
        SecureRandom random = new SecureRandom();
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        if(!algo.contains("ECB")){
            bc.init(Cipher.ENCRYPT_MODE,key,ivParam);
            bgm.init(Cipher.ENCRYPT_MODE,key,ivParam);
        }else{
            bc.init(Cipher.ENCRYPT_MODE,key);
            bgm.init(Cipher.ENCRYPT_MODE,key);
        }
        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText,bgmCipherText);
        if(!algo.contains("ECB")){
            bc.init(Cipher.DECRYPT_MODE,key,ivParam);
            bgm.init(Cipher.DECRYPT_MODE,key,ivParam);
        }else {
            bc.init(Cipher.DECRYPT_MODE,key);
            bgm.init(Cipher.DECRYPT_MODE,key);
        }
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText,bgmPlainText);
    }

    public static void testAEADMode(String algo,Key key, int tLen,int ivLen,int plainTextLen) throws Exception{
        Cipher bc = Cipher.getInstance(algo,"BC");
        Cipher bgm = Cipher.getInstance(algo,"BGMJCEProvider");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        int aadLen = (((int) (Math.random() * 32767)) + 1);
        byte[] aad = new byte[aadLen];
        random.nextBytes(aad);
        GCMParameterSpec gcmParameterSpec  = null;
        if(!algo.contains("CCM")){
            gcmParameterSpec = new GCMParameterSpec(tLen, iv);
            bc.init(Cipher.ENCRYPT_MODE,key,gcmParameterSpec);
            bgm.init(Cipher.ENCRYPT_MODE,key,gcmParameterSpec);
        }else{
            bc.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));
            bgm.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] plainText = new byte[plainTextLen];
        random.nextBytes(plainText);

        byte[] bcCipherText = bc.doFinal(plainText);
        byte[] bgmCipherText = bgm.doFinal(plainText);
        Assert.assertArrayEquals(bcCipherText,bgmCipherText);

        if(!algo.contains("CCM")){
            bc.init(Cipher.DECRYPT_MODE,key,gcmParameterSpec);
            bgm.init(Cipher.DECRYPT_MODE,key,gcmParameterSpec);
        }else{
            bc.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
            bgm.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
        }
        bc.updateAAD(aad);
        bgm.updateAAD(aad);
        byte[] bcPlainText = bc.doFinal(bcCipherText);
        byte[] bgmPlainText = bgm.doFinal(bgmCipherText);
        Assert.assertArrayEquals(bcPlainText,bgmPlainText);
    }


}
