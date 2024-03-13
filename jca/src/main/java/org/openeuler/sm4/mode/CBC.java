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

import javax.crypto.*;
import java.util.Arrays;

/**
 * SM4 CBC mode
 */
public class CBC extends StreamModeBaseCipher {
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
        if (opmode == Cipher.ENCRYPT_MODE) {
            encryptCBC(input, inputOffset, len, output, outputOffset);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            decryptCBC(input, inputOffset, len, output, outputOffset);
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
        if (opmode == Cipher.ENCRYPT_MODE) {
            encryptCBC(input, inputOffset, len, res, 0);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            decryptCBC(input, inputOffset, len, res, 0);
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
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                if ((inputLenUpdate - len + inputLen) % 16 != 0) {
                    throw new IllegalBlockSizeException();
                }
            }
            int length = engineGetOutputSize(inputLenUpdate - len + inputLen);
            res = new byte[length];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else if (restLen == 16) {
                encryptCBC(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, res, 0);
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
                    encryptCBC(block, 0, 16, res, 0);
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, res, 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if ((inputLen + inputLenUpdate - len) % 16 != 0) {
                throw new IllegalBlockSizeException();
            }
            if (restLen == 0) {
                if (inputLen == 0) {
                    this.reset();
                    return res;
                } else {
                    res = decryptLastBlock(input, inputOffset, inputLen, 0, null);
                    decryptCBC(input, inputOffset, inputLen - 16, res, 0);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    res = decryptLastBlock(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, 0, null);
                } else {
                    if (inputLen == 16) {
                        res = decryptLastBlock(input, inputOffset, inputLen, 16, Arrays.copyOfRange(inputUpdate, inputOffsetUpdate + len, inputOffsetUpdate + len + 16));
                    } else {
                        res = decryptLastBlock(input, inputOffset, inputLen, 16, null);
                    }

                    decryptCBC(inputUpdate, inputOffsetUpdate + len, 16, res, 0);
                    decryptCBC(input, inputOffset, inputLen - 16, res, 16);
                }
            } else {
                byte[] block = new byte[16];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                if (inputLen == 16 - restLen) {
                    res = decryptLastBlock(block, 0, 16, 0, null);
                } else {
                    if (inputLen - 16 + restLen == 16) {
                        res = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16, block);
                    } else {
                        res = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16, null);
                    }
                    decryptCBC(block, 0, 16, res, 0);
                    decryptCBC(input, inputOffset + 16 - restLen, inputLen - 32 + restLen, res, 16);
                }
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
                if ((inputLenUpdate - len + inputLen) % 16 != 0) {
                    throw new IllegalBlockSizeException();
                }
            }
            need = engineGetOutputSize(inputLenUpdate - len + inputLen);
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset);
            } else if (restLen == 16) {
                encryptCBC(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, output, outputOffset);
                encrypt(input, inputOffset, inputLen, output, 16 + outputOffset);
            } else {
                if (16 - restLen > inputLen) {
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    byte[] fill = padding.fill(block);
                    encrypt(block, 0, 16, output, outputOffset);
                } else {
                    byte[] block = new byte[16];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    encryptCBC(block, 0, 16, output, outputOffset);
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, output, outputOffset + 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if ((inputLen + inputLenUpdate - len) % 16 != 0) {
                throw new IllegalBlockSizeException();
            }
            if (restLen == 0) {
                if (inputLen == 0) {
                    return 0;
                } else {
                    need = decryptLastBlock(input, inputOffset, inputLen, 0, output, outputOffset, null);
                    decryptCBC(input, inputOffset, inputLen - 16, output, outputOffset);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    need = decryptLastBlock(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, 0, output, outputOffset, null);
                } else {
                    if (inputLen == 16) {
                        need = decryptLastBlock(input, inputOffset, inputLen, 16, output, outputOffset, Arrays.copyOfRange(inputUpdate, inputOffsetUpdate + len, inputOffsetUpdate + len + 16));
                    } else {
                        need = decryptLastBlock(input, inputOffset, inputLen, 16, output, outputOffset, null);
                    }
                    decryptCBC(inputUpdate, inputOffsetUpdate + len, 16, output, outputOffset);
                    decryptCBC(input, inputOffset, inputLen - 16, output, outputOffset + 16);
                }
            } else {
                byte[] block = new byte[16];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                if (inputLen == 16 - restLen) {
                    need = decryptLastBlock(block, 0, 16, 0, output, outputOffset, null);
                } else {
                    if (inputLen - 16 + restLen == 16) {
                        need = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16, output, outputOffset, block);
                    } else {
                        need = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16, output, outputOffset, null);
                    }
                    decryptCBC(block, 0, 16, output, outputOffset);
                    decryptCBC(input, inputOffset + 16 - restLen, inputLen - 32 + restLen, output, outputOffset + 16);
                }
            }
        }
        this.reset();
        return need;
    }

    /**
     * decrypt the last block and return an array containing the decrypted result.
     * if there is padding the length of the final result can only be determined if the last block is decrypted.
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param extra       the number of bytes required in addition to the input data
     * @param cipher
     * @return byte array which contain the last block decrypted and whose length is extra+inputLen-16+(lastBlockDecrypted).length
     * @throws BadPaddingException
     */
    private byte[] decryptLastBlock(byte[] input, int inputOffset, int inputLen, int extra, byte[] cipher) throws BadPaddingException {
        byte[] res;
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            res = new byte[inputLen + extra];
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                if (cipher == null) {
                    xor = sm4.xor(decrypt, counter);
                } else {
                    xor = sm4.xor(decrypt, cipher);
                }
                sm4.copyArray(xor, 0, xor.length, res, res.length - 16);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] xor = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                sm4.copyArray(xor, 0, xor.length, res, res.length - 16);
            }
        } else {
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                if (cipher == null) {
                    xor = sm4.xor(decrypt, counter);
                } else {
                    xor = sm4.xor(decrypt, cipher);
                }
                byte[] recover = this.padding.recover(xor);
                res = new byte[recover.length + extra];
                sm4.copyArray(recover, 0, recover.length, res, res.length - recover.length);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] last128BitPlainTextWithPadding = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                byte[] lastNoPaddingPlainText = this.padding.recover(last128BitPlainTextWithPadding);
                res = new byte[inputLen - 16 + lastNoPaddingPlainText.length + extra];
                sm4.copyArray(lastNoPaddingPlainText, 0, lastNoPaddingPlainText.length, res, res.length - lastNoPaddingPlainText.length);
            }
        }

        return res;

    }

    /**
     * decrypting the last block and return  the number of bytes required to store the decryption result
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param extra
     * @param output
     * @param outputOffset
     * @param cipher
     * @return
     * @throws BadPaddingException
     * @throws ShortBufferException
     */
    private int decryptLastBlock(byte[] input, int inputOffset, int inputLen, int extra, byte[] output, int outputOffset, byte[] cipher) throws BadPaddingException, ShortBufferException {
        int need = 0;
        if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            need = inputLen + extra;
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                if (cipher == null) {
                    xor = sm4.xor(decrypt, counter);
                } else {
                    xor = sm4.xor(decrypt, cipher);
                }
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + need - 16);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] xor = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                sm4.copyArray(xor, 0, xor.length, output, outputOffset + need - 16);
            }

        } else {
            if (inputLen == 16) {
                byte[] decrypt = sm4.decrypt(this.rk, input, inputOffset);
                byte[] xor = null;
                if (cipher == null) {
                    xor = sm4.xor(decrypt, counter);
                } else {
                    xor = sm4.xor(decrypt, cipher);
                }
                byte[] recover = this.padding.recover(xor);
                need = recover.length + extra;
                sm4.copyArray(recover, 0, recover.length, output, outputOffset + need - recover.length);
            } else {
                byte[] last128bit = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
                byte[] last128BitPlainTextWithPadding = sm4.xor(last128bit, 0, 16, input, inputLen + inputOffset - 32, 16);
                byte[] lastNoPaddingPlainText = this.padding.recover(last128BitPlainTextWithPadding);
                need = inputLen - 16 + lastNoPaddingPlainText.length + extra;
                if (outputOffset + need > output.length) {
                    throw new ShortBufferException();
                }
                sm4.copyArray(lastNoPaddingPlainText, 0, lastNoPaddingPlainText.length, output, outputOffset + need - lastNoPaddingPlainText.length);
            }
        }

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
    private void decryptCBC(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
            byte[] decrypt = sm4.decrypt(this.rk, input, i);
            byte[] xor = sm4.xor(decrypt, counter);
            sm4.copyArray(input, i, 16, counter, 0);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
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
        int limitOffset = inputOffset + inputLen - 16;
        int baseOffset = outputOffset - inputOffset;
        int i;
        for (i = inputOffset; i <= limitOffset; i += 16) {
            byte[] xor = sm4.xor(counter, 0, counter.length, input, i, 16);
            byte[] encrypt = sm4.encrypt(this.rk, xor);
            this.counter = encrypt;
            sm4.copyArray(encrypt, 0, encrypt.length, output, baseOffset + i);
        }
        if (inputLen % 16 != 0) {
            byte[] fill = this.padding.fill(input, i, inputLen % 16);
            byte[] xor = sm4.xor(counter, fill);
            byte[] encrypt = sm4.encrypt(this.rk, xor);
            this.counter = encrypt;
            sm4.copyArray(encrypt, 0, encrypt.length, output, baseOffset + i);
        }
        if (inputLen % 16 == 0 && !this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            byte[] block = new byte[16];
            Arrays.fill(block, (byte) 16);
            byte[] xor = sm4.xor(counter, block);
            byte[] encrypt = sm4.encrypt(this.rk, xor);
            this.counter = encrypt;
            sm4.copyArray(encrypt, 0, encrypt.length, output, baseOffset + i);
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
    private void encryptCBC(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        int limitOffset = inputOffset + inputLen - 16;
        int baseOffset = outputOffset - inputOffset;
        for (int i = inputOffset; i <= limitOffset; i += 16) {
            byte[] xor = sm4.xor(counter, 0, counter.length, input, i, 16);
            byte[] encrypt = sm4.encrypt(this.rk, xor);
            this.counter = encrypt;
            sm4.copyArray(encrypt, 0, encrypt.length, output, baseOffset + i);
        }
    }

    @Override
    public void reset() {
        super.reset();
        sm4.copyArray(iv, 0, iv.length, counter, 0);
    }
}
