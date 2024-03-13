/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * SM4 CTR mode
 */
public class CTR extends StreamModeBaseCipher {

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
        init(opmode, key);
        if (params == null) {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                //generate iv
                if (random == null) {
                    random = BGMJCEProvider.getRandom();
                }
                this.iv = new byte[16];
                random.nextBytes(this.iv);
            } else if (this.opmode == Cipher.DECRYPT_MODE) {
                throw new InvalidAlgorithmParameterException("need an IV");
            }
        } else {
            if (!(params instanceof IvParameterSpec)) {
                throw new InvalidAlgorithmParameterException();
            } else {
                IvParameterSpec param = (IvParameterSpec) params;
                if (param.getIV().length < 8 || param.getIV().length > 16) {
                    throw new InvalidAlgorithmParameterException("IV must be 8-16 bytes long.");
                }
                this.iv = param.getIV();
            }
        }
        sm4.copyArray(iv, 0, iv.length, counter, 0);
        isInitialized = true;
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            return inputLen;
        }
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (inputLen % 16 == 0) {
                return inputLen + 16;
            } else {
                return inputLen + 16 - (inputLen % 16);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (inputLen % 16 != 0) {
                return 0;
            } else {
                return inputLen;
            }
        }
        return 0;
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
        if (padding.getPadding().toUpperCase().equals("NOPADDING")) {
            if (inputLen < 16) {
                len = 0;
                return null;
            } else {
                len = inputLen - (inputLen % 16);
            }
        } else {
            if (inputLen <= 16) {
                len = 0;
                return null;
            } else if (inputLen % 16 == 0) {
                len = inputLen - 16;
            } else {
                len = inputLen - (inputLen % 16);
            }
        }
        res = new byte[len];
        processCTR(input, inputOffset, len, res, 0);
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
        if (padding.getPadding().toUpperCase().equals("NOPADDING")) {
            if (inputLen < 16) {
                len = 0;
                return 0;
            } else {
                len = inputLen - (inputLen % 16);
            }
        } else {
            if (inputLen <= 16) {
                len = 0;
                return 0;
            } else if (inputLen % 16 == 0) {
                len = inputLen - 16;
            } else {
                len = inputLen - (inputLen % 16);
            }
        }
        if (outputOffset + len > output.length) {
            throw new ShortBufferException();
        }
        processCTR(input, inputOffset, len, output, outputOffset);
        return len;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = null;
        int restLen = inputLenUpdate - len;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            int length = engineGetOutputSize(restLen + inputLen);
            res = new byte[length];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else if (restLen == 16) {
                processCTR(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, res, 0);
                encrypt(input, inputOffset, inputLen, res, 16);
            } else {
                if (16 - restLen > inputLen) {
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    encrypt(block, 0, block.length, res, 0);
                } else {
                    byte[] block = new byte[16];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    processCTR(block, 0, 16, res, 0);
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, res, 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            byte[] tem = new byte[inputLen + inputLenUpdate - len];
            if (restLen == 0) {
                if (inputLen == 0) {
                    this.reset();
                    return res;
                } else {
                    decrypt(input, inputOffset, inputLen, tem, 0);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    decrypt(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, tem, 0);
                } else {
                    processCTR(inputUpdate, inputOffsetUpdate + len, 16, tem, 0);
                    decrypt(input, inputOffset, inputLen, tem, 16);
                }
            } else {
                if (inputLen <= 16 - restLen) {
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    decrypt(block, 0, block.length, tem, 0);
                } else {
                    byte[] block = new byte[16];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    processCTR(block, 0, 16, tem, 0);
                    decrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, tem, 16);
                }
            }
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                res = tem;
            } else {
                res = this.padding.recover(tem);
            }
        }

        this.reset();
        return res;

    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] bytes = engineDoFinal(input, inputOffset, inputLen);
        if (bytes != null) {
            if (outputOffset + bytes.length > output.length) {
                throw new ShortBufferException("buffer is too short.");
            } else {
                sm4.copyArray(bytes, 0, bytes.length, output, outputOffset);
            }
            return bytes.length;
        } else {
            return 0;
        }
    }

    /**
     * encrypt with handling padding
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            int i;
            for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                byte[] encrypt = null;
                byte[] xor = null;
                encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                xor = sm4.xor(encrypt, 0, 16, input, i, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
            if (inputLen % 16 != 0) {
                byte[] encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                byte[] xor = sm4.xor(encrypt, 0, 16, input, i, inputLen % 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
        } else {
            int i;
            for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                byte[] encrypt = null;
                byte[] xor = null;
                encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                xor = sm4.xor(encrypt, 0, 16, input, i, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
            if (inputLen % 16 != 0) {
                byte[] fill = this.padding.fill(input, i, inputLen % 16);
                byte[] encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                byte[] xor = sm4.xor(encrypt, 0, 16, fill, 0, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
            if (inputLen % 16 == 0 && !this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                byte[] block = new byte[16];
                Arrays.fill(block, (byte) 16);
                byte[] encrypt = sm4.encrypt(this.rk, counter, 0);
                incrementCount();
                byte[] xor = sm4.xor(encrypt, block);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
        }
    }

    /**
     * decrypt without handling padding
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void decrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            int i;
            for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                byte[] encrypt = null;
                byte[] xor = null;
                encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                xor = sm4.xor(encrypt, 0, 16, input, i, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
            if (inputLen % 16 != 0) {
                byte[] encrypt = sm4.encrypt(this.rk, this.counter, 0);
                incrementCount();
                byte[] xor = sm4.xor(encrypt, 0, 16, input, i, inputLen % 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
            }
        } else {
            processCTR(input, inputOffset, inputLen, output, outputOffset);
        }
    }

    /**
     * implement counter increment
     */
    private void incrementCount() {
        int r = counter.length - 1;
        for (; r >= 0; ) {
            try {
                this.counter[r] = increment(r);
                break;
            } catch (Exception e) {
                r--;
            }
        }
        if (r == -1) {
            for (int i = 0; i < counter.length; i++) {
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
     * encrypt(decrypt) entire blocks of data
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void processCTR(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
            byte[] encrypt = sm4.encrypt(this.rk, counter, 0);
            incrementCount();
            byte[] xor = sm4.xor(encrypt, 0, 16, input, i, 16);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
    }

    @Override
    public void reset() {
        inputUpdate = null;
        inputLenUpdate = 0;
        len = 0;
        System.arraycopy(iv, 0, counter, 0, iv.length);
        for (int i = iv.length; i < counter.length; i++) {
            counter[i] = (byte) 0;
        }
    }
}
