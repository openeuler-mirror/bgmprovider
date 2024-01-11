/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

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
 * SM4 CCM mode
 * refer to RFC3610
 */
public class CCM extends StreamModeBaseCipher {

    private int M = 8; //number of octets in authentication field
    private int L;//number of octets in length field
    private final int defaultIvLen = 12;
    private byte[] B = new byte[BLOCKSIZE];
    private byte[] counter0 = new byte[BLOCKSIZE]; //CTR0
    private byte[] aad; //additional authentication data
    private byte[] lenA;

    @Override
    public void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

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
            if (params instanceof IvParameterSpec) {
                IvParameterSpec param = (IvParameterSpec) params;
                this.iv = param.getIV();
            } else if (params instanceof GCMParameterSpec) {
                GCMParameterSpec param = (GCMParameterSpec) params;
                int tagLen = param.getTLen();
                if (tagLen < 32 || tagLen > 128 || ((tagLen & 0x0F) != 0)) {
                    throw new InvalidAlgorithmParameterException
                            ("Unsupported TLen value; must be one of " +
                                    "{128, 112, 96, 80, 64, 48, 32}");
                }
                this.M = tagLen >> 3;
                this.iv = param.getIV();
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported parameter: " + params);
            }
            if (this.iv.length < 7 || this.iv.length > 13) {
                throw new InvalidAlgorithmParameterException("nonce must have length from 7 to 13 octets");
            }
        }
        L = 15 - iv.length;
        getCountero();
        sm4.copyArray(counter0, 0, counter0.length, counter, 0);
        incr();
        this.isInitialized = true;
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
    public int engineGetOutputSize(int inputLen) {
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            return inputLen + M;
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            return inputLen - M;
        }
        return 0;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!this.isInitialized) {
            throw new IllegalStateException("cipher uninitiallized");
        } else {
            aad = Arrays.copyOfRange(src, offset, len);
        }
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        len = 0;
        return 0;
    }

    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        len = 0;
        return null;
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
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = null;
        int restLen = inputLenUpdate - len;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            res = new byte[restLen + inputLen + M];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, res, 0);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < M) {
                throw new IllegalBlockSizeException();
            }
            if (restLen == 0) {
                res = decrypt(input, inputOffset, inputLen);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                res = decrypt(allInput, 0, allInput.length);
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
            need = restLen + inputLen + M;
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, output, outputOffset);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen + inputLen < M) {
                throw new IllegalBlockSizeException();
            }
            need = inputLen - M;
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (restLen == 0) {
                byte[] decrypt = decrypt(input, inputOffset, inputLen);
                sm4.copyArray(decrypt, 0, decrypt.length, output, outputOffset);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                byte[] decrypt = decrypt(allInput, 0, allInput.length);
                sm4.copyArray(decrypt, 0, decrypt.length, output, outputOffset);
            }
        }
        reset();
        return need;
    }

    /**
     * get the CTR0 according to iv
     */
    private void getCountero() {
        counter0[0] = (byte) (L - 1);
        for (int i = 1; i <= 15 - L; i++) {
            counter0[i] = this.iv[i - 1];
        }

    }

    /**
     * CCM counter increment
     */
    private void incr() {
        int r = counter.length - 1;
        for (; r >= 16 - L; ) {
            try {
                this.counter[r] = increment(r);
                break;
            } catch (Exception e) {
                r--;
            }
        }
        if (r == 15 - L) {
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
     * @return
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
     * CCM encrypt
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        byte[] plainText = null;
        if (inputLen != 0) {
            plainText = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        }
        byte[] tag = getTag(plainText);
        if (plainText != null) {
            int i;
            for (i = 0; i + 16 <= plainText.length; i += 16) {
                byte[] encrypt = sm4.encrypt(this.rk, counter, 0);
                incr();
                byte[] xor = sm4.xor(encrypt, 0, 16, plainText, i, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i);
            }
            if (plainText.length % 16 != 0) {
                byte[] encrrypt = sm4.encrypt(this.rk, counter, 0);
                incr();
                byte[] xor = sm4.xor(plainText, i, plainText.length % 16, encrrypt, 0, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i);
            }
        }
        sm4.copyArray(tag, 0, tag.length, output, outputOffset + inputLen);
    }

    /**
     * CCM decrypt
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
     */
    private byte[] decrypt(byte[] input, int inputOffset, int inputLen) {
        byte[] fill = Arrays.copyOfRange(input, inputOffset, inputLen + inputOffset - M);
        byte[] res = new byte[fill.length];
        byte[] _T = Arrays.copyOfRange(input, inputOffset + inputLen - M, inputLen + inputOffset);
        int i;
        for (i = 0; i + 16 <= fill.length; i += 16) {
            byte[] curBlock = Arrays.copyOfRange(fill, i, i + 16);
            byte[] encrypt = sm4.encrypt(this.rk, counter, 0);
            incr();
            byte[] xor = sm4.xor(encrypt, curBlock);
            sm4.copyArray(xor, 0, xor.length, res, i);
        }
        if (fill.length % 16 != 0) {
            byte[] encrrypt = sm4.encrypt(this.rk, counter, 0);
            incr();
            byte[] xor = sm4.xor(Arrays.copyOfRange(fill, i, fill.length), encrrypt);
            sm4.copyArray(xor, 0, xor.length, res, res.length - xor.length);
        }

        checkMac(_T, getTag(res));
        return res;
    }

    @Override
    public void reset() {
        super.reset();
        aad = null;
        Arrays.fill(B, (byte) 0);
        L = 15 - iv.length;
        getCountero();
        sm4.copyArray(counter0, 0, counter0.length, counter, 0);
        incr();
        lenA = null;

    }

    /**
     * generate authentication tag
     *
     * @param plainText
     * @return
     */
    private byte[] getTag(byte[] plainText) {
        //consttructor B0
        B[0] = (byte) ((byte) ((M - 2) / 2) << 3);
        if (aad == null || aad.length == 0) {
            B[0] &= 0xbf;
        } else {
            B[0] |= 0x40;
        }
        byte tem = (byte) (L - 1);
        tem &= 0x07;
        B[0] |= tem;
        sm4.copyArray(iv, 0, iv.length, B, 1);
        readInt(B, plainText == null ? 0 : plainText.length, 16 - L);
        B = sm4.encrypt(this.rk, sm4.xor(B, new byte[16]), 0);

        if (aad != null && aad.length != 0) {
            if (aad.length < 65280) {
                lenA = new byte[2];
                readInt(lenA, aad.length, 0);
            } else {
                lenA = new byte[6];
                lenA[0] = (byte) 0xff;
                lenA[1] = (byte) 0xfe;
                sm4.intToBigEndian(lenA, aad.length, 2);
            }
        }
        if (lenA != null) {
            if (aad.length + lenA.length >= 16) {
                int needLen = BLOCKSIZE - lenA.length;
                byte[] block = new byte[BLOCKSIZE];
                sm4.copyArray(lenA, 0, lenA.length, block, 0);
                sm4.copyArray(Arrays.copyOfRange(aad, 0, needLen), 0, needLen, block, lenA.length);
                B = sm4.encrypt(this.rk, sm4.xor(B, block), 0);
                int i;
                for (i = needLen; i + 16 <= aad.length; i += 16) {
                    B = sm4.encrypt(this.rk, sm4.xor(B, Arrays.copyOfRange(aad, i, i + 16)), 0);
                }
                if ((aad.length - needLen) % 16 != 0) {
                    block = new byte[BLOCKSIZE];
                    sm4.copyArray(aad, i, aad.length - i, block, 0);
                    B = sm4.encrypt(this.rk, sm4.xor(B, block), 0);
                }
            } else {
                byte[] block = new byte[BLOCKSIZE];
                sm4.copyArray(lenA, 0, lenA.length, block, 0);
                sm4.copyArray(aad, 0, aad.length, block, lenA.length);
                B = sm4.encrypt(this.rk, sm4.xor(B, block), 0);

            }
        }
        if (plainText != null) {
            int i;
            for (i = 0; i + 16 <= plainText.length; i += 16) {
                B = sm4.encrypt(this.rk, sm4.xor(B, Arrays.copyOfRange(plainText, i, i + 16)), 0);
            }
            if (plainText.length % 16 != 0) {
                byte[] block = new byte[BLOCKSIZE];
                sm4.copyArray(plainText, i, plainText.length - i, block, 0);
                B = sm4.encrypt(this.rk, sm4.xor(B, block), 0);
            }
        }

        byte[] encrypt = sm4.encrypt(this.rk, counter0, 0);
        return Arrays.copyOfRange(sm4.xor(encrypt, B), 0, M);
    }

    /**
     * convert x into byte array
     *
     * @param arr   store the convert result
     * @param x     to be converted data
     * @param start offset of arr
     */
    private void readInt(byte[] arr, int x, int start) {
        if (arr.length - start >= 4) {
            sm4.intToBigEndian(arr, x, arr.length - 4);
        } else if (arr.length - start == 3) {
            arr[start] = (byte) ((x << 8) >>> 24);
            start++;
            arr[start] = (byte) ((x << 16) >>> 24);
            start++;
            arr[start] = (byte) ((x << 24) >>> 24);
        } else if (arr.length - start == 2) {
            arr[start] = (byte) ((x << 16) >>> 24);
            start++;
            arr[start] = (byte) ((x << 24) >>> 24);
        } else if (arr.length - start == 1) {
            arr[start] = (byte) ((x << 24) >>> 24);
        }
    }

    /**
     * determine whether the authentication tag is consistent
     *
     * @param T  the calculated tag
     * @param _T tag in cipherText
     */
    private void checkMac(byte[] T, byte[] _T) {
        if (!Arrays.equals(T, _T)) {
            throw new RuntimeException("mac check failed in CCM mode.");
        }
    }

}
