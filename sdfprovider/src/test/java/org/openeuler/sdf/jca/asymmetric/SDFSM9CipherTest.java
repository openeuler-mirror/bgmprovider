package org.openeuler.sdf.jca.asymmetric;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.sdf.commons.constant.SDFDataKeyType;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.*;
import java.util.Arrays;

public class SDFSM9CipherTest extends SDFTestCase {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static PublicKey signPublicKey;
    private static PrivateKey signPrivateKey;
    private static Key key;

    static {
        System.setProperty("sdf.sdkConfig", SDFTestUtil.getSdkConfig());
        System.setProperty("sdf.defaultKEKId", new String(SDFTestUtil.getTestKekId()));
        System.setProperty("sdf.defaultRegionId", new String(SDFTestUtil.getTestRegionId()));
        System.setProperty("sdf.defaultCdpId", new String(SDFTestUtil.getTestCdpId()));
    }

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        Security.insertProviderAt(new SDFProvider(), 1);
        KeyPairGenerator sm9EncMaster = KeyPairGenerator.getInstance("SM9Enc");
        sm9EncMaster.initialize(256);
        KeyPair keyPair = sm9EncMaster.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        KeyPairGenerator sm9SignMaster = KeyPairGenerator.getInstance("SM9Sign");
        sm9SignMaster.initialize(256);
        KeyPair signKeyPair = sm9SignMaster.generateKeyPair();
        signPublicKey = signKeyPair.getPublic();
        signPrivateKey = signKeyPair.getPrivate();

        KeyGenerator sm4Gen = KeyGenerator.getInstance("SM4", "BGMJCEProvider");
        key = sm4Gen.generateKey();
    }

    @Test
    public void testSDFSM9Cipher() throws Exception {
        Cipher cipher = Cipher.getInstance("SM9");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] plainText = new byte[100];
        Arrays.fill(plainText, (byte) 1);
        byte[] encData = cipher.doFinal(plainText);
        System.out.println("encData=" + Arrays.toString(encData));

        cipher = Cipher.getInstance("SM9");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decData = cipher.doFinal(encData);
        System.out.println("decData=" + Arrays.toString(decData));
        Assert.assertArrayEquals(plainText, decData);
    }

    @Test
    public void testSDFSM9Sign() throws Exception {
        Signature signature = Signature.getInstance("SM9");
        signature.setParameter(new SDFSM9ParameterSpec(new KeyPair(signPublicKey, signPrivateKey)));
        signature.initSign(signPrivateKey);
        byte[] data = "Test data".getBytes();
        signature.update(data);
        byte[] signed = signature.sign();
        System.out.println("signed=" + Arrays.toString(signed));

        signature.initVerify(signPublicKey);
        signature.update(data);
        boolean verify = signature.verify(signed);
        Assert.assertTrue(verify);
    }

    @Test
    public void testSDFSM9WrapAndUnwrap() throws Exception {
        Cipher cipher = Cipher.getInstance("SM9");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] wrapped = cipher.wrap(signPublicKey);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        Key unwrapped = cipher.unwrap(wrapped, "SM9", Cipher.PUBLIC_KEY);
        Assert.assertArrayEquals(signPublicKey.getEncoded(), unwrapped.getEncoded());

        cipher.init(Cipher.WRAP_MODE, publicKey);
        byte[] wrappedKey = cipher.wrap(key);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        Key unwrappedKey = cipher.unwrap(wrappedKey, "SM9", Cipher.SECRET_KEY);
        Assert.assertArrayEquals(key.getEncoded(), unwrappedKey.getEncoded());
    }
}
