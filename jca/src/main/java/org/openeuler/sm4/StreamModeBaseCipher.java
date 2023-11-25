package org.openeuler.sm4;

import org.openeuler.BGMJCEProvider;

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
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        String paramType = null;
        if (params != null) {
            try {
                paramType = "IV";
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException
                        ("Wrong parameter type: " + paramType + " expected");
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        super.engineInit(opmode, key, params, random);
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate iv
                this.iv = new byte[16];
                if (random == null) {
                    random = BGMJCEProvider.getRandom();
                }
                random.nextBytes(iv);
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
        isInitialized = true;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return null;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
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
