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

import org.openeuler.sm4.StreamModeBaseCipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.util.Arrays;

/**
 * SM4 CTS mode
 */
public class CTS extends StreamModeBaseCipher {

    @Override
    public int engineGetOutputSize(int inputLen) {
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                return inputLen;
            } else {
                return inputLen + 16 - (inputLen % 16);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                return inputLen;
            } else {
                if (inputLen % 16 != 0) {
                    return 0;
                } else {
                    return inputLen;
                }
            }
        }
        return 0;
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
            } else if (inputLen % 16 != 0) {
                len = inputLen - (16 + (inputLen % 16));
            } else if (inputLen == 16) {
                len = 0;
                return 0;
            } else {
                len = inputLen - 32;
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
        if (opmode == Cipher.ENCRYPT_MODE) {
            encryptCTS(input, inputOffset, len, output, outputOffset);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            decryptCTS(input, inputOffset, len, output, outputOffset);
        }
        return len;
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
            } else if (inputLen % 16 != 0) {
                len = inputLen - (16 + (inputLen % 16));
                if (len == 0) return null;
            } else if (inputLen == 16) {
                len = 0;
                return null;
            } else {
                len = inputLen - 32;
                if (len == 0) return null;
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
        if (opmode == Cipher.ENCRYPT_MODE) {
            encryptCTS(input, inputOffset, len, res, 0);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            decryptCTS(input, inputOffset, len, res, 0);
        }
        return res;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = null;
        int restLen = inputLenUpdate - len;
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            if (restLen + inputLen < 16) {
                throw new IllegalBlockSizeException("CTS nopadding need at least 1 block input.");
            }
        }
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            int length = engineGetOutputSize(inputLenUpdate - len + inputLen);
            res = new byte[length];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, res, 0);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen == 0) {
                res = decrypt(input, inputOffset, inputLen);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                res = decrypt(allInput, 0, allInput.length);
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
        int restLen = inputLenUpdate - len;
        int need = 0;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                if (restLen + inputLen < 16) {
                    throw new IllegalBlockSizeException("CTS nopadding need at least 1 block plainText");
                }
            }
            int length = engineGetOutputSize(inputLenUpdate - len + inputLen);
            need = length;
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                encrypt(allInput, 0, allInput.length, output, outputOffset);
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if (restLen == 0) {
                need = decrypt(input, inputOffset, inputLen, output, outputOffset);
            } else {
                byte[] allInput = new byte[restLen + inputLen];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, allInput, 0);
                sm4.copyArray(input, inputOffset, inputLen, allInput, restLen);
                need = decrypt(allInput, 0, allInput.length, output, outputOffset);
            }
        }
        this.reset();
        return need;
    }

    /**
     * decrypt entire blocks of data
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void decryptCTS(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
            byte[] decrypt = sm4.decrypt(this.rk, input, i);
            byte[] xor = sm4.xor(decrypt, counter);
            sm4.copyArray(input, i, 16, counter, 0);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
    }

    /**
     * encrypt entire blocks of data
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void encryptCTS(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
            byte[] xor = sm4.xor(counter, 0, counter.length, input, i, 16);
            byte[] encrypt = sm4.encrypt(this.rk, xor);
            this.counter = encrypt;
            sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + i - inputOffset);
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
            if (inputLen % 16 != 0) {
                int i;
                for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                    byte[] xor = null;
                    xor = sm4.xor(input, i, 16, this.counter, 0, 16);
                    byte[] encrypt = sm4.encrypt(this.rk, xor, 0);
                    this.counter = encrypt;
                    if (!(i + 32 > inputLen + inputOffset)) {
                        sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + i - inputOffset);
                    }
                }
                int needLen = BLOCKSIZE - (inputLen % 16);
                byte[] xor = sm4.xor(input, inputOffset + inputLen - (inputLen % 16), inputLen % 16, counter, 0, 16);
                byte[] block = new byte[BLOCKSIZE];
                sm4.copyArray(xor, 0, xor.length, block, 0);
                sm4.copyArray(counter, counter.length - needLen, needLen, block, block.length - needLen);
                byte[] encrypt = sm4.encrypt(this.rk, block, 0);
                sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + i - inputOffset - 16);
                sm4.copyArray(counter, 0, inputLen % 16, output, outputOffset + i - inputOffset);

            } else {
                for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                    byte[] xor = null;
                    xor = sm4.xor(input, i, 16, this.counter, 0, 16);
                    byte[] encrypt = sm4.encrypt(this.rk, xor, 0);
                    this.counter = encrypt;
                    sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + i - inputOffset);
                }
                if (inputLen != 16) {
                    byte tmp;
                    for (int i = 0; i < BLOCKSIZE; i++) {
                        tmp = output[outputOffset + inputLen - 32 + i];
                        output[outputOffset + inputLen - 32 + i] = output[outputOffset + inputLen - 16 + i];
                        output[outputOffset + inputLen - 16 + i] = tmp;
                    }
                }
            }


        } else {
            int i;
            for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
                byte[] xor = sm4.xor(counter, 0, counter.length, input, i, 16);
                byte[] encrypt = sm4.encrypt(this.rk, xor);
                this.counter = encrypt;
                sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + i - inputOffset);
            }
            if (inputLen % 16 != 0) {
                byte[] fill = this.padding.fill(input, i, inputLen % 16);
                byte[] xor = sm4.xor(counter, fill);
                byte[] encrypt = sm4.encrypt(this.rk, xor);
                this.counter = encrypt;
                sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + (i - inputOffset));
            }
            if (inputLen % 16 == 0) {
                byte[] block = new byte[16];
                Arrays.fill(block, (byte) 16);
                byte[] xor = sm4.xor(counter, block);
                byte[] encrypt = sm4.encrypt(this.rk, xor);
                this.counter = encrypt;
                sm4.copyArray(encrypt, 0, encrypt.length, output, outputOffset + (i - inputOffset));
            }
        }
    }

    /**
     * decrypt with handling padding and return the decrypted result
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return the decrypted result
     * @throws BadPaddingException
     */
    private byte[] decrypt(byte[] input, int inputOffset, int inputLen) throws BadPaddingException {
        byte[] res = null;
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            res = new byte[inputLen];
            if (inputLen % 16 != 0) {
                int needLen = BLOCKSIZE - (inputLen % 16);
                int i;
                for (i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                    byte[] decrypt = sm4.decrypt(this.rk, input, i);
                    if (!(i + 32 > +inputOffset+inputLen)) {
                        byte[] xor = null;
                        xor = sm4.xor(decrypt, this.counter);
                        sm4.copyArray(input, i, 16, counter, 0);
                        sm4.copyArray(xor, 0, xor.length, res, i - inputOffset);
                    } else {
                        byte[] block = new byte[BLOCKSIZE];
                        sm4.copyArray(input, inputOffset + inputLen - (inputLen % 16), inputLen % 16, block, 0);
                        sm4.copyArray(decrypt, decrypt.length - needLen, needLen, block, block.length - needLen);
                        byte[] decrypt1 = sm4.decrypt(this.rk, block, 0);
                        byte[] xor = sm4.xor(decrypt1, counter);
                        sm4.copyArray(xor, 0, xor.length, res, i - inputOffset);
                        this.counter = decrypt;
                    }
                }

                byte[] e = Arrays.copyOfRange(input, inputLen + inputOffset - (inputLen % 16), inputLen + inputOffset);
                byte[] xor = sm4.xor(e, counter);
                sm4.copyArray(xor, 0, xor.length, res, res.length - xor.length);

            } else {
                if (inputLen != 16) {
                    byte tmp;
                    for (int i = 0; i < BLOCKSIZE; i++) {
                        tmp = input[inputLen + inputOffset - 32 + i];
                        input[inputLen + inputOffset - 32 + i] = input[inputOffset + inputLen - 16 + i];
                        input[inputOffset + inputLen - 16 + i] = tmp;
                    }
                }
                for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                    byte[] decrypt = sm4.decrypt(this.rk, input, i);
                    byte[] xor = null;
                    xor = sm4.xor(decrypt, this.counter);
                    sm4.copyArray(input, i, 16, counter, 0);
                    sm4.copyArray(xor, 0, xor.length, res, i - inputOffset);
                }
                if (inputLen != 16) {
                    byte tmp;
                    for (int i = 0; i < BLOCKSIZE; i++) {
                        tmp = input[inputLen + inputOffset - 32 + i];
                        input[inputLen + inputOffset - 32 + i] = input[inputOffset + inputLen - 16 + i];
                        input[inputOffset + inputLen - 16 + i] = tmp;
                    }
                }
            }
        } else {
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                xor = sm4.xor(decrypt, counter);
                byte[] recover = this.padding.recover(xor);
                res = new byte[recover.length];
                sm4.copyArray(recover, 0, recover.length, res, res.length - recover.length);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] last128BitPlainTextWithPadding = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                byte[] lastNoPaddingPlainText = this.padding.recover(last128BitPlainTextWithPadding);
                res = new byte[inputLen - 16 + lastNoPaddingPlainText.length];
                sm4.copyArray(lastNoPaddingPlainText, 0, lastNoPaddingPlainText.length, res, res.length - lastNoPaddingPlainText.length);
                decryptCTS(input, inputOffset, inputLen - 16, res, 0);
            }
        }
        return res;
    }

    /**
     * decrypt with handling padding and return  the length of the decrypted result
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     * @return the length of the decrypted result
     * @throws BadPaddingException
     * @throws ShortBufferException
     */
    private int decrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws BadPaddingException, ShortBufferException {
        int need = 0;
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            need = inputLen;
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (inputLen % 16 != 0) {
                int needLen = BLOCKSIZE - (inputLen % 16);
                int i;
                for (i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                    byte[] decrypt = sm4.decrypt(this.rk, input, i);
                    if (!(i + 32 > inputOffset+inputLen)) {
                        byte[] xor = null;
                        xor = sm4.xor(decrypt, this.counter);
                        sm4.copyArray(input, i, 16, counter, 0);
                        sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
                    } else {
                        byte[] block = new byte[BLOCKSIZE];
                        sm4.copyArray(input, inputOffset + inputLen - (inputLen % 16), inputLen % 16, block, 0);
                        sm4.copyArray(decrypt, decrypt.length - needLen, needLen, block, block.length - needLen);
                        byte[] decrypt1 = sm4.decrypt(this.rk, block, 0);
                        byte[] xor = sm4.xor(decrypt1, counter);
                        sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
                        this.counter = decrypt;
                    }
                }

                byte[] e = Arrays.copyOfRange(input, inputLen + inputOffset - (inputLen % 16), inputLen + inputOffset);
                byte[] xor = sm4.xor(e, counter);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + need - xor.length);

            } else {
                if (inputLen != 16) {
                    byte tmp;
                    for (int i = 0; i < BLOCKSIZE; i++) {
                        tmp = input[inputLen + inputOffset - 32 + i];
                        input[inputLen + inputOffset - 32 + i] = input[inputOffset + inputLen - 16 + i];
                        input[inputOffset + inputLen - 16 + i] = tmp;
                    }
                }
                for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
                    byte[] decrypt = sm4.decrypt(this.rk, input, i);
                    byte[] xor = null;
                    xor = sm4.xor(decrypt, this.counter);
                    sm4.copyArray(input, i, 16, counter, 0);
                    sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
                }

                if (inputLen != 16) {
                    byte tmp;
                    for (int i = 0; i < BLOCKSIZE; i++) {
                        tmp = input[inputLen + inputOffset - 32 + i];
                        input[inputLen + inputOffset - 32 + i] = input[inputOffset + inputLen - 16 + i];
                        input[inputOffset + inputLen - 16 + i] = tmp;
                    }
                }
            }
        } else {
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                xor = sm4.xor(decrypt, counter);
                byte[] recover = this.padding.recover(xor);
                need = recover.length;
                if (outputOffset + need > output.length) {
                    throw new ShortBufferException();
                }
                sm4.copyArray(recover, 0, recover.length, output, outputOffset + need - recover.length);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] last128BitPlainTextWithPadding = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                byte[] lastNoPaddingPlainText = this.padding.recover(last128BitPlainTextWithPadding);
                need = inputLen - 16 + lastNoPaddingPlainText.length;
                sm4.copyArray(lastNoPaddingPlainText, 0, lastNoPaddingPlainText.length, output, outputOffset + need - lastNoPaddingPlainText.length);
                decryptCTS(input, inputOffset, inputLen - 16, output, outputOffset);
            }
        }
        return need;
    }

    @Override
    public void reset() {
        super.reset();
        sm4.copyArray(iv, 0, iv.length, counter, 0);
    }
}

