package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;
import org.openeuler.sdf.commons.util.SDFTestUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

public class SDFSymmetricTestUtil {
    public static SecretKey generateKey(String algorithm, Provider provider, int keySize, boolean isEncKey)
            throws Exception {
        KeyGenerator keyGenerator = getKeyGenerator(algorithm, provider);
        if (isEncKey) {
            keyGenerator.init(new SDFKeyGeneratorParameterSpec(
                    SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(),
                    SDFTestUtil.getTestCdpId(),
                    SDFTestUtil.getTestPin(),
                    keySize
            ));
        } else {
            keyGenerator.init(keySize);
        }
        return keyGenerator.generateKey();
    }

    private static KeyGenerator getKeyGenerator(String algorithm, Provider provider) throws Exception {
        KeyGenerator keyGenerator;
        if (provider != null) {
            keyGenerator = KeyGenerator.getInstance(algorithm, provider);
        } else {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        }
        return keyGenerator;
    }

    public static byte[] encryptUpdate(String algorithm, Provider provider, SecretKey secretKey,
                                       AlgorithmParameterSpec spec, byte[] data) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.update(data);
    }

    public static byte[] encryptUpdate(String algorithm, Provider provider, SecretKey secretKey,
                                       AlgorithmParameterSpec spec, byte[] data, int offset, int len) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.update(data, offset, len);
    }

    public static byte[] decryptUpdate(String algorithm, Provider provider, SecretKey secretKey,
                                       AlgorithmParameterSpec spec, byte[] data) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.update(data);
    }

    public static byte[] decryptUpdate(String algorithm, Provider provider, SecretKey secretKey,
                                       AlgorithmParameterSpec spec, byte[] data, int offset ,int len) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.update(data, offset, len);
    }

    public static byte[] encryptDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                        AlgorithmParameterSpec spec, byte[] data) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(data);
    }


    public static byte[] encryptDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                        AlgorithmParameterSpec spec, byte[] data, int offset, int len)
            throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(data, offset, len);
    }

    public static byte[] decryptDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                        AlgorithmParameterSpec spec, byte[] data) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.doFinal(data);
    }


    public static byte[] decryptDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                        AlgorithmParameterSpec spec, byte[] data, int offset, int len)
            throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.doFinal(data, offset, len);
    }

    public static byte[] encryptUpdateAndDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                                 AlgorithmParameterSpec spec, byte[] data) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] updateBytes = cipher.update(data);
        if (updateBytes != null) {
            out.write(updateBytes);
        }
        byte[] doFinalBytes = cipher.doFinal();
        if (doFinalBytes != null) {
            out.write(doFinalBytes);
        }
        return out.toByteArray();
    }


    public static byte[] encryptUpdateAndDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                                 AlgorithmParameterSpec spec, byte[] data,int offset ,int len)
            throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] updateBytes = cipher.update(data, offset, len);
        if (updateBytes != null) {
            out.write(updateBytes);
        }
        byte[] doFinalBytes = cipher.doFinal();
        if (doFinalBytes != null) {
            out.write(doFinalBytes);
        }
        return out.toByteArray();
    }

    public static byte[] decryptUpdateAndDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                                 AlgorithmParameterSpec spec, byte[] encryptedData) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        if (isECBMode(algorithm)) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] updateBytes = cipher.update(encryptedData);
        if (updateBytes != null) {
            out.write(updateBytes);
        }

        byte[] doFinalBytes = cipher.doFinal();
        if (doFinalBytes != null) {
            out.write(doFinalBytes);
        }
        return out.toByteArray();
    }


    public static byte[] decryptUpdateAndDoFinal(String algorithm, Provider provider, SecretKey secretKey,
                                                 AlgorithmParameterSpec spec, byte[] encryptedData, int offset,
                                                 int len) throws Exception {
        Cipher cipher = getCipher(algorithm, provider);
        if (isECBMode(algorithm)) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] updateBytes = cipher.update(encryptedData, offset, len);
        if (updateBytes != null) {
            out.write(updateBytes);
        }

        byte[] doFinalBytes = cipher.doFinal();
        if (doFinalBytes != null) {
            out.write(doFinalBytes);
        }
        return out.toByteArray();
    }

    public static boolean isNoPadding(String algorithm) {
        return algorithm.toUpperCase().contains("NOPADDING");
    }

    public static Cipher getCipher(String algorithm, Provider provider) throws Exception {
        Cipher cipher;
        if (provider != null) {
            cipher = Cipher.getInstance(algorithm, provider);
        } else  {
            cipher = Cipher.getInstance(algorithm);
        }
        return cipher;
    }

    /*public static byte[] update(Cipher cipher, byte[] data) {
        return cipher.update(data);
    }
    public static byte[] doFinal(Cipher cipher, byte[] data) {
        return cipher.update(data);
    }*/

    private static boolean isECBMode(String algorithm) {
        return algorithm.toUpperCase().contains("ECB");
    }

    private static boolean isGCMMode(String algorithm) {
        return algorithm.toUpperCase().contains("GCM");
    }

    public static AlgorithmParameterSpec getAlgorithmParameterSpec(String algorithm, int tagLen, byte[] iv) {
        if (isECBMode(algorithm)) {
            return null;
        } else if (isGCMMode(algorithm)) {
            return new GCMParameterSpec(tagLen, iv);
        } else {
            return new IvParameterSpec(iv);
        }
    }
}
