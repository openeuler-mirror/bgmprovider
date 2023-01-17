package org.openeuler.sm4.mode;

import org.openeuler.sm4.GMacUtil;
import org.openeuler.sm4.StreamModeBaseCipher;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * SM4 GCM mode
 * refer to: https://zh.wikipedia.org/wiki/%E4%BC%BD%E7%BD%97%E7%93%A6/%E8%AE%A1%E6%95%B0%E5%99%A8%E6%A8%A1%E5%BC%8F
 * refer to: nistspecialpublication800-38d
 */
public class GCM extends StreamModeBaseCipher {
    private byte[] T;// authentication tag.
    private byte[] aad;//additional authentication data
    private byte[] H;//hash subkey H=sm4.encrypt(key,new byte[16])
    private byte[] g;//intermediate authentication parameters
    private final int defaultIvLen = 12;
    private int tLen = 128;//default 128 bits
    private byte[] counter0;//CTR0
    private int aLen;//aad's length
    private int cLen;//cipherText's length
    private byte[] updateData;//save the data operated by calling update method

    @Override
    public void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if ((key == null) || ((key != null) && (!(key instanceof SecretKey) || key.getEncoded().length != 16))) {
            throw new InvalidKeyException();
        }
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            //generate iv
            this.iv = new byte[defaultIvLen];
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            random.nextBytes(this.iv);
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("need Ivparam");
        }
        this.key = (SecretKey) key;
        this.opmode = opmode;
        this.random = random;
        H = sm4.encrypt(key.getEncoded(), new byte[16], 0);
        counter0 = GMacUtil.getCounter0(iv, H);
        sm4.copyArray(counter0, 0, counter0.length, counter, 0);
        inc32();
        this.isInitialized = true;

    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if ((key == null) || ((key != null) && (!(key instanceof SecretKey) || key.getEncoded().length != 16))) {
            throw new InvalidKeyException();
        }
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate IV
                if (this.random == null) {
                    this.random = new SecureRandom();
                }
                this.iv = new byte[defaultIvLen];
                this.random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV");
            }
        } else {
            if (!(params instanceof GCMParameterSpec)) {
                if (!(params instanceof IvParameterSpec)) {
                    throw new InvalidAlgorithmParameterException();
                } else {
                    IvParameterSpec param = (IvParameterSpec) params;
                    if (param.getIV() == null || param.getIV().length < 1) {
                        throw new InvalidAlgorithmParameterException("IV at least 1 byte long.");
                    }
                    if (Arrays.equals(this.iv, param.getIV()) && opmode == Cipher.ENCRYPT_MODE) {
                        throw new InvalidAlgorithmParameterException("cannot reuse nonce for GCM encryption");
                    }
                    this.iv = param.getIV();
                }
            } else {
                GCMParameterSpec gcmParam = (GCMParameterSpec) params;
                checkTagLen(gcmParam);
                if (gcmParam.getIV() == null || gcmParam.getIV().length < 1) {
                    throw new InvalidAlgorithmParameterException("IV at least 1 byte long.");
                }
                if (Arrays.equals(this.iv, gcmParam.getIV()) && opmode == Cipher.ENCRYPT_MODE) {
                    throw new InvalidAlgorithmParameterException("cannot reuse nonce for GCM encryption");
                }
                this.tLen = gcmParam.getTLen();
                this.iv = gcmParam.getIV();
            }

        }
        this.opmode = opmode;
        this.key = (SecretKey) key;
        this.random = random;
        H = sm4.encrypt(key.getEncoded(), new byte[16], 0);
        counter0 = GMacUtil.getCounter0(iv, H);
        sm4.copyArray(counter0, 0, counter0.length, counter, 0);
        inc32();
        this.isInitialized = true;
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
                this.iv = new byte[defaultIvLen];
                this.random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV.");
            }
        } else {
            IvParameterSpec parameterSpec = null;
            GCMParameterSpec gcmParameterSpec = null;
            try {
                gcmParameterSpec = params.getParameterSpec(GCMParameterSpec.class);
            } catch (InvalidParameterSpecException invalidParameterSpecException) {

            }
            if (gcmParameterSpec == null) {
                try {
                    parameterSpec = params.getParameterSpec(IvParameterSpec.class);
                } catch (InvalidParameterSpecException e) {
                }

                if (parameterSpec == null) {
                    throw new InvalidAlgorithmParameterException();
                } else {
                    if (parameterSpec.getIV() == null || parameterSpec.getIV().length < 1) {
                        throw new InvalidAlgorithmParameterException("IV at least 1 byte long.");
                    }
                    if (Arrays.equals(this.iv, parameterSpec.getIV()) && opmode == Cipher.ENCRYPT_MODE) {
                        throw new InvalidAlgorithmParameterException("cannot reuse nonce for GCM encryption");
                    }
                    this.iv = parameterSpec.getIV();
                }
            } else {
                if (gcmParameterSpec.getIV() == null || gcmParameterSpec.getIV().length < 1) {
                    throw new InvalidAlgorithmParameterException("IV at least 1 byte long.");
                }
                checkTagLen(gcmParameterSpec);
                if (Arrays.equals(this.iv, gcmParameterSpec.getIV()) && opmode == Cipher.ENCRYPT_MODE) {
                    throw new InvalidAlgorithmParameterException("cannot reuse nonce for GCM encryption");
                }
                this.tLen = gcmParameterSpec.getTLen();
                this.iv = gcmParameterSpec.getIV();
            }
        }
        this.opmode = opmode;
        this.key = (SecretKey) key;
        this.random = random;
        H = sm4.encrypt(key.getEncoded(), new byte[16], 0);
        counter0 = GMacUtil.getCounter0(iv, H);
        sm4.copyArray(counter0, 0, counter0.length, counter, 0);
        inc32();
        this.isInitialized = true;
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            return inputLen + (this.tLen / 8);
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            return inputLen - (tLen / 8);
        }
        return 0;
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        AlgorithmParameters sm4Paraeters = null;
        try {
            sm4Paraeters = AlgorithmParameters.getInstance("SM4");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sm4Paraeters.init(new GCMParameterSpec(tLen, iv));
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }

        return sm4Paraeters;
    }

    @Override
    public void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.toUpperCase().equals("NOPADDING")) {
            throw new NoSuchPaddingException("only nopadding can be used in this mode");
        } else {
            super.engineSetPadding(padding);
        }
    }

    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        if (input == null || inputLen == 0) {
            return null;
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        byte[] res = null;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            len = inputLen - (inputLen % 16);
            if (len == 0) {
                return null;
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            len = inputLen - (tLen / 8);
            len = len - (len % 16);
            if (len <= 0) {
                len = 0;
                return null;
            }

        }
        cLen += len * 8;
        res = new byte[len];
        processGCM(input, inputOffset, len, res, 0);
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            updateData = res;
        }
        return res;
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = engineUpdate(input, inputOffset, inputLen);
        if (res == null) {
            return 0;
        }
        if (res.length + outputOffset > output.length) {
            throw new ShortBufferException("buffer is too short");
        }
        sm4.copyArray(res, 0, res.length, output, outputOffset);
        return res.length;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        int need = 0;
        int restLen = inputLenUpdate - len;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            need = restLen + inputLen + (tLen / 8);
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            boolean first = false;
            if (aad == null) {
                if (updateData == null) {
                    first = true;
                } else {
                    for (int i = 0; i + 16 <= updateData.length; i += 16) {
                        if (i == 0) {
                            processG(Arrays.copyOfRange(updateData, i, i + 16), true);
                        } else {
                            processG(Arrays.copyOfRange(updateData, i, i + 16), false);
                        }
                    }
                }

            } else {
                if (updateData != null) {
                    for (int i = 0; i + 16 <= updateData.length; i += 16) {
                        processG(Arrays.copyOfRange(updateData, i, i + 16), false);
                    }
                }
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset, first);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, output, outputOffset, first);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < tLen / 8) {
                throw new IllegalBlockSizeException();
            }
            boolean first = false;
            if (aad == null) {
                if (len == 0) {
                    first = true;
                } else {
                    for (int i = inputOffsetUpdate; i + 16 <= len + inputOffsetUpdate; i += 16) {
                        if (i == inputOffsetUpdate) {
                            processG(Arrays.copyOfRange(inputUpdate, i, i + 16), true);
                        } else {
                            processG(Arrays.copyOfRange(inputUpdate, i, i + 16), false);
                        }
                    }
                }
            } else {
                if (len != 0) {
                    for (int i = inputOffsetUpdate; i + 16 <= len + inputOffsetUpdate; i += 16) {
                        processG(Arrays.copyOfRange(inputUpdate, i, i + 16), false);
                    }
                }
            }
            if (restLen == 0) {
                need = inputLen - (tLen / 8);
                if (outputOffset + need > output.length) {
                    throw new ShortBufferException();
                }
                decrypt(input, inputOffset, inputLen, output, outputOffset, first);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                need = inputLen + restLen - (tLen / 8);
                if (outputOffset + need > output.length) {
                    throw new ShortBufferException();
                }
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                decrypt(allInput, 0, allInput.length, output, outputOffset, first);
            }
        }
        this.reset();
        return need;
    }


    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        int restLen = inputLenUpdate - len;
        byte[] res = null;

        if (this.opmode == Cipher.ENCRYPT_MODE) {
            res = new byte[restLen + inputLen + (tLen / 8)];
            boolean first = false;
            if (aad == null) {
                if (updateData == null) {
                    first = true;
                } else {
                    for (int i = 0; i + 16 <= updateData.length; i += 16) {
                        if (i == 0) {
                            processG(Arrays.copyOfRange(updateData, i, i + 16), true);
                        } else {
                            processG(Arrays.copyOfRange(updateData, i, i + 16), false);
                        }
                    }
                }

            } else {
                if (updateData != null) {
                    for (int i = 0; i + 16 <= updateData.length; i += 16) {
                        processG(Arrays.copyOfRange(updateData, i, i + 16), false);
                    }
                }
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0, first);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, res, 0, first);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < tLen / 8) {
                throw new IllegalBlockSizeException();
            }
            boolean first = false;
            if (aad == null) {
                if (len == 0) {
                    first = true;
                } else {
                    for (int i = inputOffsetUpdate; i + 16 <= len + inputOffsetUpdate; i += 16) {
                        if (i == inputOffsetUpdate) {
                            processG(Arrays.copyOfRange(inputUpdate, i, i + 16), true);
                        } else {
                            processG(Arrays.copyOfRange(inputUpdate, i, i + 16), false);
                        }
                    }
                }
            } else {
                if (len != 0) {
                    for (int i = inputOffsetUpdate; i + 16 <= len + inputOffsetUpdate; i += 16) {
                        processG(Arrays.copyOfRange(inputUpdate, i, i + 16), false);
                    }
                }
            }
            if (restLen == 0) {
                res = new byte[inputLen - (tLen / 8)];
                decrypt(input, inputOffset, inputLen, res, 0, first);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                res = new byte[inputLen + restLen - (tLen / 8)];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                decrypt(allInput, 0, allInput.length, res, 0, first);
            }
        }
        this.reset();
        return res;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!this.isInitialized) {
            throw new IllegalStateException("cipher uninitiallized");
        } else {
            aLen = len;
            aad = new byte[len];
            sm4.copyArray(src, offset, len, aad, 0);
            processG(aad, true);
        }
    }


    /**
     * check if the mac size is valid
     *
     * @param spec
     * @return
     * @throws InvalidAlgorithmParameterException
     */
    private boolean checkTagLen(GCMParameterSpec spec) throws InvalidAlgorithmParameterException {
        //tLen:128,120,112,104,96
        int len = spec.getTLen();
        if (len != 96 && len != 104 && len != 112 && len != 120 && len != 128) {
            throw new InvalidAlgorithmParameterException("invalid mac size " + len);
        }
        return true;
    }

    /**
     * determine whether the authentication tag is consistent
     *
     * @param T  the calculated tag
     * @param _T tag in cipherText
     * @return
     */
    private boolean checkMac(byte[] T, byte[] _T) {
        if (!Arrays.equals(T, _T)) {
            throw new RuntimeException("mac check in GCM failed");
        } else {
            return true;
        }
    }

    /**
     * encrypt(decrypt) entire blocks of data
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void processGCM(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
            byte[] encrypt = sm4.encrypt(key.getEncoded(), counter, 0);
            inc32();
            byte[] xor = sm4.xor(encrypt, 0, 16, input, i, 16);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
    }


    /**
     * encrypt and generate authentication tag
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     * @param first
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, boolean first) {
        if (inputLen == 0) {
            byte[] AC = new byte[16];
            aLen = (aLen * 8);
            sm4.readInt(AC, aLen, 4);
            sm4.readInt(AC, cLen, 12);

            byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
            if(aad==null && updateData==null){
                processG(AC, true);
            }else{
                processG(AC,false);
            }
            T = sm4.xor16Byte(g, encrypt0);
            sm4.copyArray(T, 0, tLen / 8, output, outputOffset + inputLen);
        } else if (inputLen < 16) {
            byte[] xor = null;
            //对计数器加密
            byte[] encrypt = sm4.encrypt(this.key.getEncoded(), this.counter, 0);
            inc32();
            xor = sm4.xor(encrypt, 0, 16, input, inputOffset, inputLen);
            processG(xor, first);

            //len(A)||len(C)
            byte[] AC = new byte[16];
            aLen = (aLen * 8);
            cLen = cLen + (xor.length * 8);
            sm4.readInt(AC, aLen, 4);
            sm4.readInt(AC, cLen, 12);

            byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
            processG(AC, false);
            T = sm4.xor16Byte(g, encrypt0);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset);
            sm4.copyArray(T, 0, tLen / 8, output, outputOffset + inputLen);
        } else {
            for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                byte[] encrypt = null;
                byte[] xor = null;
                encrypt = sm4.encrypt(this.key.getEncoded(), this.counter, 0);
                inc32();
                xor = sm4.xor(encrypt, 0, 16, input, i, 16);
                if (i == inputOffset) {
                    processG(xor, first);
                } else {
                    processG(xor, false);
                }
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
                if (inputLen % 16 == 0 && i + 16 >= inputLen + inputOffset) {
                    byte[] AC = new byte[16];
                    aLen = (aLen * 8);
                    cLen += inputLen * 8;
                    sm4.readInt(AC, aLen, 4);
                    sm4.readInt(AC, cLen, 12);

                    byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
                    processG(AC, false);
                    T = sm4.xor16Byte(g, encrypt0);
                    sm4.copyArray(T, 0, tLen / 8, output, outputOffset + inputLen);
                }
            }
            if (inputLen % 16 != 0) {
                byte[] encrypt = sm4.encrypt(key.getEncoded(), this.counter, 0);
                inc32();
                byte[] xor = sm4.xor(encrypt, 0, 16, input, inputLen + inputOffset - (inputLen % 16), inputLen % 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + inputLen - inputLen % 16);
                processG(xor, false);

                byte[] AC = new byte[16];
                aLen = (aLen * 8);
                cLen += inputLen * 8;
                sm4.readInt(AC, aLen, 4);
                sm4.readInt(AC, cLen, 12);

                byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
                processG(AC, false);
                T = sm4.xor16Byte(g, encrypt0);
                sm4.copyArray(T, 0, tLen / 8, output, outputOffset + inputLen);
            }
        }
    }

    /**
     * decrypt and check the authentication tag
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     * @param first
     */
    private void decrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, boolean first) {
        if (inputLen - (tLen / 8) < 16) {
            byte[] cipher = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen - (tLen / 8));
            byte[] _T = Arrays.copyOfRange(input, inputOffset + inputLen - (tLen / 8), inputOffset + inputLen);

            processG(cipher, first);

            byte[] AC = new byte[16];
            aLen = (aLen * 8);
            cLen += cipher.length * 8;
            sm4.readInt(AC, aLen, 4);
            sm4.readInt(AC, cLen, 12);

            byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
            processG(AC, false);
            T = sm4.xor16Byte(g, encrypt0);
            T = Arrays.copyOfRange(T, 0, _T.length);
            checkMac(T, _T);
            byte[] encrypt = sm4.encrypt(this.key.getEncoded(), this.counter, 0);
            inc32();
            byte[] xor = sm4.xor(encrypt, cipher);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset);
        } else {
            byte[] cipherText = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen - (tLen / 8));
            byte[] _T = Arrays.copyOfRange(input, inputOffset + inputLen - (tLen / 8), inputLen + inputOffset);
            for (int i = 0; i + 16 <= cipherText.length; i += 16) {
                byte[] curBlock = Arrays.copyOfRange(cipherText, i, i + 16);
                byte[] encrypt = null;
                byte[] xor = null;
                encrypt = sm4.encrypt(this.key.getEncoded(), this.counter, 0);
                inc32();
                if (i == 0) {
                    processG(curBlock, first);
                } else {
                    processG(curBlock, false);
                }
                xor = sm4.xor(encrypt, curBlock);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i);
                if (cipherText.length % 16 == 0 && i + 16 >= cipherText.length) {
                    byte[] AC = new byte[16];
                    aLen = (aLen * 8);
                    cLen += cipherText.length * 8;
                    sm4.readInt(AC, aLen, 4);
                    sm4.readInt(AC, cLen, 12);

                    byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
                    processG(AC, false);
                    T = sm4.xor16Byte(g, encrypt0);
                    T = Arrays.copyOfRange(T, 0, _T.length);
                    checkMac(T, _T);
                }
            }
            if (cipherText.length % 16 != 0) {
                byte[] curBlock = Arrays.copyOfRange(cipherText, cipherText.length - (cipherText.length % 16), cipherText.length);
                byte[] encrypt = sm4.encrypt(key.getEncoded(), this.counter, 0);
                inc32();
                byte[] xor = sm4.xor(encrypt, curBlock);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + inputLen - (tLen / 8) - (cipherText.length % 16));
                processG(curBlock, false);

                byte[] AC = new byte[16];
                aLen = (aLen * 8);
                cLen += (inputLen - (tLen / 8)) * 8;
                sm4.readInt(AC, aLen, 4);
                sm4.readInt(AC, cLen, 12);

                byte[] encrypt0 = sm4.encrypt(key.getEncoded(), counter0, 0);
                processG(AC, false);
                T = sm4.xor16Byte(g, encrypt0);
                T = Arrays.copyOfRange(T, 0, _T.length);
                checkMac(T, _T);
            }
        }
    }

    /**
     * GCM incrementing function
     */
    private void inc32() {
        int r = counter.length - 1;
        for (; r >= 12; ) {
            try {
                this.counter[r] = increment(r);
                break;
            } catch (Exception e) {
                r--;
            }
        }
        if (r == 11) {
            for (int i = 12; i < counter.length; i++) {
                this.counter[i] = 0;
            }
        }

    }

    /**
     * determines whether the binary bit of counter[index] contains zeros
     * if it contains zero, it changes the rightmost zero to 1 and all binary positions to its right to 0
     * if it does not contain 0, it throws an exception
     *
     * @param index
     * @return value of counter[index] after the change
     * @throws Exception
     */
    private byte increment(int index) throws Exception {
        int i = 0;
        for (; i < 8; i++) {
            if (((1 << i) & counter[index]) == 0) {
                break;
            }
        }
        if (i == 8) {
            throw new Exception();
        } else {
            counter[index] = (byte) ((1 << i) | counter[index]);
            int t = 0;
            for (int j = 7; j >= i; j--) {
                t |= (1 << j);
            }
            for (int k = index + 1; k < counter.length; k++) {
                this.counter[k] = 0;
            }
            return (byte) (t & counter[index]);
        }
    }

    /**
     * process intermediate authentication parameters
     *
     * @param cipherText aad or cipherText
     * @param first      indicates if this is the first time the function has been called
     */
    private void processG(byte[] cipherText, boolean first) {
        if (cipherText.length < 16) {
            byte[] arr = new byte[16];
            sm4.copyArray(cipherText, 0, cipherText.length, arr, 0);
            cipherText = arr;
        }
        if (first) {
            if (cipherText.length > 16) {
                byte[] arr = null;
                if (cipherText.length % 16 != 0) {
                    arr = new byte[cipherText.length + 16 - (cipherText.length % 16)];
                    sm4.copyArray(cipherText, 0, cipherText.length, arr, 0);
                } else {
                    arr = cipherText;
                }
                for (int i = 0; i + 16 <= arr.length; i += 16) {
                    if (i == 0) {
                        g = GMacUtil.mult(H, org.bouncycastle.util.Arrays.copyOfRange(arr, i, i + 16));
                    } else {
                        g = sm4.xor16Byte(g, Arrays.copyOfRange(arr, i, i + 16));
                        g = GMacUtil.mult(g, H);
                    }
                }
            } else {
                g = GMacUtil.mult(H, cipherText);
            }
        } else {
            g = sm4.xor16Byte(g, cipherText);
            g = GMacUtil.mult(g, H);
        }
    }

    @Override
    public void reset() {
        super.reset();
        T = null;
        aad = null;
        cLen = 0;
        aLen = 0;
        isInitialized = false;
        g = null;
        H = null;
        updateData = null;
    }
}
