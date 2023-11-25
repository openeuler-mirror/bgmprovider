package org.openeuler.sm4.mode;

import org.openeuler.BGMJCEProvider;
import org.openeuler.sm4.StreamModeBaseCipher;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * SM4 OCB mode
 * refer to RFC7253
 */
public class OCB extends StreamModeBaseCipher {
    private byte[] aad;//additional authentication data
    private int defaultIvLen = 15;
    private int tLen = 128;
    private byte[] H;//H=sm4.encrypt(key,new byte[16])
    private byte[] L_$;
    private byte[][] L;
    private byte[] L_0;
    private byte[] nonce;
    private byte[] checkSum;
    private byte[] offset;
    private byte[] ktop;
    private byte bottom;
    private byte[] stretch;
    private byte[] tag;//authentication tag


    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate IV
                if (random == null) {
                    random = BGMJCEProvider.getRandom();
                }
                this.iv = new byte[defaultIvLen];
                random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV");
            }
        } else {
            if (!(params instanceof GCMParameterSpec)) {
                if (!(params instanceof IvParameterSpec)) {
                    throw new InvalidAlgorithmParameterException();
                } else {
                    IvParameterSpec param = (IvParameterSpec) params;
                    if (param.getIV() == null || param.getIV().length > 15) {
                        throw new InvalidAlgorithmParameterException("IV no more than 15 bytes long.");
                    }
                    this.iv = param.getIV();
                }
            } else {
                GCMParameterSpec gcmParam = (GCMParameterSpec) params;
                checkTagLen(gcmParam);
                if (gcmParam.getIV() == null || gcmParam.getIV().length > 15) {
                    throw new InvalidAlgorithmParameterException("IV no more than 15 bytes long.");
                }
                this.tLen = gcmParam.getTLen();
                this.iv = gcmParam.getIV();
            }

        }
        H = sm4.encrypt(this.rk, new byte[BLOCKSIZE], 0);
        L_$ = double_(H);
        L_0 = double_(L_$);
        init();
        isInitialized = true;
    }

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
                paramType = "GCM or IV";
                spec = params.getParameterSpec(GCMParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                try {
                    spec = params.getParameterSpec(IvParameterSpec.class);
                } catch (InvalidParameterSpecException ex) {
                    throw new InvalidAlgorithmParameterException
                            ("Wrong parameter type: " + paramType + " expected");
                }
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!isInitialized) {
            throw new IllegalStateException("cipher uninitialized");
        }
        if (offset == 0 && len == src.length) {
            aad = src;
        } else {
            aad = Arrays.copyOfRange(src, offset, offset + len);
        }
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            return inputLen + (tLen / 8);
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            return inputLen - (tLen / 8);
        }
        return 0;
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
        checkSum = new byte[BLOCKSIZE];
        res = new byte[len];
        initL(len / 16);
        processOCB(input, inputOffset, len, res, 0);
        return res;
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        if (input == null || inputLen == 0) {
            return 0;
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            len = inputLen - (inputLen % 16);
            if (len == 0) {
                return 0;
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            len = inputLen - (tLen / 8);
            len = len - (len % 16);
            if (len <= 0) {
                len = 0;
                return 0;
            }

        }
        checkSum = new byte[BLOCKSIZE];
        initL(len / 16);
        processOCB(input, inputOffset, len, output, outputOffset);
        return len;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        int restLen = inputLenUpdate - len;
        byte[] res = null;

        if (this.opmode == Cipher.ENCRYPT_MODE) {
            res = new byte[inputLen + restLen + tLen / 8];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else {
                byte[] allInput = new byte[inputLen + restLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, res, 0);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < tLen / 8) {
                throw new IllegalBlockSizeException();
            }
            res = new byte[inputLen + restLen - (tLen / 8)];
            if (restLen == 0) {
                decrypt(input, inputOffset, inputLen, res, 0);
            } else {
                byte[] allInput = new byte[inputLen + restLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                decrypt(allInput, 0, allInput.length, res, 0);
            }
        }
        reset();
        return res;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        int restLen = inputLenUpdate - len;
        int need = 0;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            need = inputLen + restLen + tLen / 8;
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset);
            } else {
                byte[] allInput = new byte[inputLen + restLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, output, outputOffset);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < tLen / 8) {
                throw new IllegalBlockSizeException();
            }
            need = inputLen + restLen - (tLen / 8);
            if (restLen == 0) {
                decrypt(input, inputOffset, inputLen, output, outputOffset);
            } else {
                byte[] allInput = new byte[inputLen + restLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                decrypt(allInput, 0, allInput.length, output, outputOffset);
            }
        }
        reset();
        return need;
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
    private void processOCB(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                offset = sm4.xor(offset, 0, 16, L[ntz((i - inputOffset) / 16 + 1)], 0, 16);
                byte[] xor1 = sm4.xor(offset, 0, 16, sm4.encrypt(this.rk, sm4.xor(offset, 0, 16, input, i, 16), 0), 0, 16);
                sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + (i - inputOffset));
                checkSum = sm4.xor(checkSum, 0, 16, input, i, 16);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                offset = sm4.xor(offset, L[ntz((i - inputOffset) / 16 + 1)]);
                byte[] xor1 = sm4.xor(offset, sm4.decrypt(this.rk, sm4.xor(offset, 0, 16, input, i, 16), 0));
                sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + i - inputOffset);
                checkSum = sm4.xor(checkSum, xor1);
            }
        }
    }

    /**
     * hash function
     *
     * @return the result of hash
     */
    private byte[] hash() {

        if (aad == null || aad.length == 0) {
            return new byte[BLOCKSIZE];
        }
        int m = (aad.length * 8) / 128;

        L = new byte[m + 1][];
        L[0] = L_0;
        for (int i = 1; i < L.length; i++) {
            L[i] = double_(L[i - 1]);
        }

        byte[] sum = new byte[BLOCKSIZE];
        byte[] offset = new byte[BLOCKSIZE];
        for (int i = 0; i < m; i++) {
            offset = sm4.xor(offset, 0, 16, L[ntz(i + 1)], 0, 16);
            sum = sm4.xor(sum, 0, 16, sm4.encrypt(this.rk, sm4.xor(Arrays.copyOfRange(aad, i * 16, (i + 1) * 16), 0, 16, offset, 0, 16), 0), 0, 16);
        }

        if (aad.length % 16 != 0) {
            offset = sm4.xor(offset, H);
            byte[] cipherInput = new byte[BLOCKSIZE];
            sm4.copyArray(aad, aad.length - (aad.length % 16), aad.length % 16, cipherInput, 0);
            cipherInput[aad.length % 16] = (byte) 0x80;
            cipherInput = sm4.xor(cipherInput, offset);
            sum = sm4.xor(sum, sm4.encrypt(this.rk, cipherInput, 0));
        }

        return sum;
    }

    /**
     * refer to RFC7253 double
     *
     * @param h :input
     * @return
     */
    private byte[] double_(byte[] h) {
        byte[] res = null;
        //determines whether the most significant bit is 0
        if ((h[0] & (byte) 0x80) == 0) {
            res = moveLeftOneBit(h);
        } else {
            byte[] tem = new byte[BLOCKSIZE];
            tem[15] = (byte) 0x87;
            res = sm4.xor(moveLeftOneBit(h), tem);
        }

        return res;
    }

    /**
     * move to left one bit
     *
     * @param input to be moved byte array.
     * @return result after moving
     */
    private byte[] moveLeftOneBit(byte[] input) {
        byte[] res = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            res[i] = (byte) (input[i] << 1);
            if (i != input.length - 1) {
                int msb = ((byte) (input[i + 1] & 0x80) == 0 ? 0 : 1);
                if (msb == 1) {
                    res[i] |= (byte) 1;
                }
            }
        }
        return res;
    }

    /**
     * The number of trailing zero bits in the base-2
     * representation of the positive integer n.
     *
     * @return
     */
    private int ntz(int num) {
        String s = Integer.toBinaryString(num);
        int sum = 0;
        for (int i = s.length() - 1; i >= 0; i--) {
            if (s.charAt(i) == '0') {
                sum++;
            } else {
                break;
            }
        }
        return sum;
    }

    /**
     * init
     */
    private void init() {
        nonce = new byte[BLOCKSIZE];
        int mod = tLen % 128;
        nonce[0] = (byte) (mod << 1);
        if (iv.length != 0) {
            int t = 16 - iv.length;
            if (iv.length == 15) {
                nonce[0] |= 1;
            } else {
                nonce[t - 1] = 1;
            }
            for (int i = 0; i < iv.length; i++) {
                nonce[i + t] = iv[i];
            }
        } else {
            nonce[15] = 1;
        }

        bottom = nonce[15];
        bottom &= 0x3f;


        byte lastByteOfNonce = nonce[15];
        nonce[15] &= 0xc0;
        ktop = sm4.encrypt(this.rk, nonce, 0);
        nonce[15] = lastByteOfNonce;
        stretch = new byte[BLOCKSIZE * 2];
        sm4.copyArray(ktop, 0, ktop.length, stretch, 0);

        byte[] xor = sm4.xor(Arrays.copyOfRange(ktop, 0, 8), Arrays.copyOfRange(ktop, 1, 9));
        for (int i = 0; i < xor.length; i++) {
            stretch[16 + i] = xor[i];
        }
        offset = new byte[BLOCKSIZE];
        for (int i = 0; i < 128; i++) {
            setI(offset, i, getI(stretch, i + bottom));
        }

    }

    /**
     * init L
     *
     * @param m
     */
    private void initL(int m) {
        L = new byte[m + 1][];
        L[0] = L_0;
        for (int i = 1; i < L.length; i++) {
            L[i] = double_(L[i - 1]);
        }
    }

    /**
     * OCB encrypt and generate authentication tag
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        initL(inputLen / 16 + len / 16);
        int i;
        if (checkSum == null) {
            checkSum = new byte[BLOCKSIZE];
        }
        for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
            offset = sm4.xor(offset, 0, 16, L[ntz(len / 16 + (i - inputOffset) / 16 + 1)], 0, 16);
            byte[] xor1 = sm4.xor(offset, 0, 16, sm4.encrypt(this.rk, sm4.xor(offset, 0, 16, input, i, 16), 0), 0, 16);
            sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + (i - inputOffset));
            checkSum = sm4.xor(checkSum, 0, 16, input, i, 16);
        }
        if (inputLen % 16 != 0) {
            offset = sm4.xor16Byte(offset, H);
            byte[] pad = sm4.encrypt(this.rk, offset, 0);
            byte[] xor1 = sm4.xor(input, inputOffset + inputLen - (inputLen % 16), inputLen % 16, pad, 0, 16);
            sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + i - inputOffset);
            byte[] tem = new byte[BLOCKSIZE];
            sm4.copyArray(input, inputOffset + inputLen - (inputLen % 16), inputLen % 16, tem, 0);
            tem[inputLen % 16] = (byte) 0x80;
            checkSum = sm4.xor(checkSum, tem);
            tag = sm4.xor(sm4.encrypt(this.rk, sm4.xor(L_$, sm4.xor(checkSum, offset)), 0), hash());
        } else {
            tag = sm4.xor(sm4.encrypt(this.rk, sm4.xor(L_$, sm4.xor(checkSum, offset)), 0), hash());
        }
        sm4.copyArray(tag, 0, tLen / 8, output, outputOffset + inputLen);
    }

    /**
     * decrypt and check the authentication tag
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void decrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        byte[] T = Arrays.copyOfRange(input, inputOffset + inputLen - (tLen / 8), inputOffset + inputLen);
        initL((inputLen - (tLen / 8)) / 16 + len / 16);
        if (checkSum == null) {
            checkSum = new byte[BLOCKSIZE];
        }
        int i;
        for (i = inputOffset; i + 16 <= inputOffset + inputLen - (tLen / 8); i += 16) {
            offset = sm4.xor(offset, L[ntz(len / 16 + (i - inputOffset) / 16 + 1)]);
            byte[] xor1 = sm4.xor(offset, sm4.decrypt(this.rk, sm4.xor(offset, 0, 16, input, i, 16), 0));
            sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + (i - inputOffset));
            checkSum = sm4.xor(checkSum, xor1);
        }
        byte[] tag = null;
        if ((inputLen - (tLen / 8)) % 16 != 0) {
            offset = sm4.xor16Byte(offset, H);
            byte[] pad = sm4.encrypt(this.rk, offset, 0);
            byte[] xor1 = sm4.xor(input, inputOffset + inputLen - (tLen / 8) - ((inputLen - (tLen / 8)) % 16), (inputLen - (tLen / 8)) % 16, pad, 0, 16);
            sm4.copyArray(xor1, 0, xor1.length, output, outputOffset + i - inputOffset);
            byte[] tem = new byte[BLOCKSIZE];
            sm4.copyArray(xor1, 0, xor1.length, tem, 0);
            tem[xor1.length] = (byte) 0x80;
            checkSum = sm4.xor(checkSum, tem);
            tag = sm4.xor(sm4.encrypt(this.rk, sm4.xor(L_$, sm4.xor(checkSum, offset)), 0), hash());
        } else {
            tag = sm4.xor(sm4.encrypt(this.rk, sm4.xor(L_$, sm4.xor(checkSum, offset)), 0), hash());
        }
        checkMac(T, Arrays.copyOfRange(tag, 0, T.length));
    }

    /**
     * get i-th bit of arr
     *
     * @param arr
     * @return 1 or 0
     */
    private int getI(byte[] arr, int i) {
        return (arr[i / 8] & (1 << (7 - (i % 8)))) == 0 ? 0 : 1;
    }

    /**
     * set arr i-th bit to target
     *
     * @param i
     * @param target 0 or 1
     */
    private void setI(byte[] arr, int i, int target) {
        if (target == 0) {
            switch (i % 8) {
                case 0: {
                    arr[i / 8] &= 0x7f;
                    break;
                }
                case 1: {
                    arr[i / 8] &= 0xbf;
                    break;
                }
                case 2: {
                    arr[i / 8] &= 0xdf;
                    break;
                }
                case 3: {
                    arr[i / 8] &= 0xef;
                    break;
                }
                case 4: {
                    arr[i / 8] &= 0xf7;
                    break;
                }
                case 5: {
                    arr[i / 8] &= 0xfb;
                    break;
                }
                case 6: {
                    arr[i / 8] &= 0xfd;
                    break;
                }
                case 7: {
                    arr[i / 8] &= 0xfe;
                    break;
                }
            }
        } else if (target == 1) {
            arr[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    /**
     * check if the mac size is valid
     *
     * @param gcmParam
     * @throws InvalidAlgorithmParameterException
     */
    private void checkTagLen(GCMParameterSpec gcmParam) throws InvalidAlgorithmParameterException {
        if (gcmParam.getTLen() % 8 != 0) {
            throw new InvalidAlgorithmParameterException("invalid  mac size " + gcmParam.getTLen());
        } else {
            if (gcmParam.getTLen() < 64 || gcmParam.getTLen() > 128) {
                throw new InvalidAlgorithmParameterException("invalid  mac size " + gcmParam.getTLen());
            }
        }
    }

    /**
     * determine whether the authentication tag is consistent
     *
     * @param T
     * @param _T
     */
    private void checkMac(byte[] T, byte[] _T) {
        if (!Arrays.equals(T, _T)) {
            throw new RuntimeException("mac check faild in OCB mode");
        }
    }

    @Override
    public void reset() {
        checkSum = null;
        aad = null;
        L = null;
        nonce = null;
        offset = null;
        ktop = null;
        stretch = null;
        tag = null;
        tLen = 128;
        H = sm4.encrypt(this.rk, new byte[BLOCKSIZE], 0);
        L_$ = double_(H);
        L_0 = double_(L_$);
        init();
        super.reset();
    }
}
