package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9PublicKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9UserPrivateKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.util.SDFSM9KeyUtil;
import org.openeuler.sdf.wrapper.SDFSM9CipherNative;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SDFSM9Cipher extends CipherSpi {
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private SDFSM9PublicKey publicKey;
    private SDFSM9UserPrivateKey privateKey;
    private int mode;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("NONE")) {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NOPADDING")) {
            throw new NoSuchPaddingException("padding not available with SDFSM2Cipher");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        init(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        update(input, inputOffset, inputLen);
        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        update(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key cannot be null");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeyException("Cannot get an encoding of key to be wrapped");
        }
        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new InvalidKeyException("The wrappedKey cannot be null or empty");
        }
        try {
            byte[] unWrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return SDFSM9KeyUtil.constructKey(wrappedKeyType, unWrappedKey, wrappedKeyAlgorithm);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] buf = doFinal(input, inputOffset, inputLen);
        System.arraycopy(buf, 0, output, outputOffset, buf.length);
        return buf.length;
    }

    private void init(int opmode, Key key) throws InvalidKeyException {
        switch (opmode) {
            case Cipher.ENCRYPT_MODE:
            case Cipher.WRAP_MODE:
                this.mode = Cipher.ENCRYPT_MODE;
                if (key instanceof SDFSM9PublicKey) {
                    this.publicKey = (SDFSM9PublicKey) key;
                }
                break;
            case Cipher.DECRYPT_MODE:
            case Cipher.UNWRAP_MODE:
                this.mode = Cipher.DECRYPT_MODE;
                if (key instanceof SDFSM9UserPrivateKey) {
                    this.privateKey = (SDFSM9UserPrivateKey) key;
                }
                break;
            default:
                throw new InvalidKeyException("Unknown mode: " + opmode);
        }
        this.buffer.reset();
    }

    private void update(byte[] input, int inputOffset, int inputLen) {
        if (inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }
    }

    private byte[] doFinal(byte[] input, int inputOffset, int inputLen) {
        update(input, inputOffset, inputLen);

        byte[] result;
        try {
            switch (mode) {
                case Cipher.ENCRYPT_MODE:
                    result = encrypt(buffer.toByteArray());
                    break;
                case Cipher.DECRYPT_MODE:
                    result = decrypt(buffer.toByteArray());
                    break;
                default:
                    throw new AssertionError("Internal error");
            }
        } finally {
            buffer.reset();
        }
        return result;
    }

    private byte[] encrypt(byte[] in) {
        if (in == null || in.length == 0) {
            throw new IllegalArgumentException("data should not be empty");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey should not be null");
        }
        try {
            return SDFSM9CipherNative.nativeSM9Encrypt(publicKey.getEncoded(), in,
                    publicKey.getEncMode(), publicKey.getHId(), publicKey.getUserId(), publicKey.getPairG());
        } catch (Exception e) {
            throw new SDFRuntimeException(e);
        }
    }

    private byte[] decrypt(byte[] in) {
        if (in == null || in.length == 0) {
            throw new IllegalArgumentException("encData should not be empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey should not be null");
        }
        try {
            return SDFSM9CipherNative.nativeSM9Decrypt(privateKey.getEncoded(), in,
                    privateKey.getEncMode(), privateKey.getUserId(), privateKey.getPairG());
        } catch (Exception e) {
            throw new SDFRuntimeException("decrypt failed.", e);
        }
    }
}
