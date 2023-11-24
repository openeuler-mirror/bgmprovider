package org.openeuler.sm4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * baseCipher of CBC CFB OFB CTR CTS GCM CCM OCB
 */
public class StreamModeBaseCipher extends SM4BaseCipher {
    protected byte[] iv;
    protected  byte[] counter = new byte[BLOCKSIZE];//data to be used in the next encryption(decryption)


    @Override
    public void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if ((key == null) || ((key != null) && (!(key instanceof SecretKey) || key.getEncoded().length != 16))) {
            throw new InvalidKeyException();
        }
        if (opmode == Cipher.ENCRYPT_MODE) {
            //generate iv
            this.opmode = opmode;
            this.key = (SecretKey) key;
            this.random = random;
            iv = new byte[BLOCKSIZE];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            random.nextBytes(iv);
            sm4.copyArray(iv,0,iv.length,counter,0);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("need Ivparam");
        }
        isInitialized = true;
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if ((key == null) || ((key != null) && (!(key instanceof SecretKey) || key.getEncoded().length != 16))) {
            throw new InvalidKeyException();
        }
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate IV
                if (this.random == null) {
                    this.random = new SecureRandom();
                }
                this.iv = new byte[16];
                this.random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV.");
            }
        } else {
            IvParameterSpec parameterSpec = null;
            try {
                parameterSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException(e);
            }
            if (parameterSpec == null) {
                throw new InvalidAlgorithmParameterException();
            }
            if (parameterSpec.getIV().length != 16) {
                throw new InvalidAlgorithmParameterException("IV must be 16 bytes long.");
            }
            this.iv = parameterSpec.getIV();
        }
        sm4.copyArray(iv, 0, iv.length, counter, 0);
        this.opmode = opmode;
        this.key = (SecretKey) key;
        this.random = random;
        isInitialized = true;
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if ((key == null) || ((key != null) && (!(key instanceof SecretKey) || key.getEncoded().length != 16))) {
            throw new InvalidKeyException();
        }
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate iv
                if (this.random == null) {
                    this.random = new SecureRandom();
                }
                this.iv = new byte[16];
                this.random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV");
            }
        } else {
            if (!(params instanceof IvParameterSpec)) {
                throw new InvalidAlgorithmParameterException();
            } else {
                IvParameterSpec param = (IvParameterSpec) params;
                if (param.getIV().length != 16) {
                    throw new InvalidAlgorithmParameterException("IV must be 16 bytes long.");
                }
                this.iv = param.getIV();
            }
        }
        sm4.copyArray(iv, 0, iv.length, counter, 0);
        this.opmode = opmode;
        this.key = (SecretKey) key;
        this.random = random;
        isInitialized = true;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return null;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    @Override
    public byte[] engineGetIV() {
        return this.iv;
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        AlgorithmParameters parameters = null;
        try {
            parameters = AlgorithmParameters.getInstance("SM4");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            parameters.init(new IvParameterSpec(this.iv));
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return parameters;
    }

    @Override
    public void reset() {
        super.reset();
        for (int i = 0; i < this.counter.length; i++) {
            counter[i]=0;
        }
    }
}
