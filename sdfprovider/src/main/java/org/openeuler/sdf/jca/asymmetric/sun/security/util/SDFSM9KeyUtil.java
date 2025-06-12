package org.openeuler.sdf.jca.asymmetric.sun.security.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public final class SDFSM9KeyUtil {
    private SDFSM9KeyUtil() {
    }

    public static Key constructKey(int keyType, byte[] encodedKey, String encodedKeyAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Key res;
        switch (keyType) {
            case Cipher.SECRET_KEY:
                res = constructSecretKey(encodedKey, encodedKeyAlgorithm);
                break;
            case Cipher.PRIVATE_KEY:
                res = constructPrivateKey(encodedKey, encodedKeyAlgorithm);
                break;
            case Cipher.PUBLIC_KEY:
                res = constructPublicKey(encodedKey, encodedKeyAlgorithm);
                break;
            default:
                throw new InvalidKeyException("Unknown keytype " + keyType);
        }
        return res;
    }

    public static PublicKey constructPublicKey(byte[] encodedKey, String encodedKeyAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("No installed providers " +
                    "can create keys for the " +
                    encodedKeyAlgorithm +
                    "algorithm");
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot construct public key");
        }
    }

    public static PrivateKey constructPrivateKey(byte[] encodedKey, String encodedKeyAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("No installed providers " +
                    "can create keys for the " +
                    encodedKeyAlgorithm +
                    "algorithm");
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot construct public key");
        }
    }

    public static SecretKey constructSecretKey(byte[] encodedKey, String encodedKeyAlgorithm) {
        return new SecretKeySpec(encodedKey, encodedKeyAlgorithm);
    }
}
