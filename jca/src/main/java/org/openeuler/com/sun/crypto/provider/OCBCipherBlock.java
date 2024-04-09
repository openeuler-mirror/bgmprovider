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

package org.openeuler.com.sun.crypto.provider;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OCBCipherBlock extends FeedbackCipher {
    // default tag len
    static final int DEFAULT_TAG_LEN = 16;
    // default iv len
    static final int DEFAULT_IV_LEN = 15;
    private int tagLen = DEFAULT_TAG_LEN;
    // L_*
    private byte[] l_sterisk;
    // L_$
    private byte[] l_dollar;
    // L_0
    private byte[] l_0;
    // L_i
    private List<byte[]> l;
    // Offset
    private byte[] offset_0;
    private byte[] offsetBlock;
    // data block, block count, block position
    private byte[] dataBlock;
    private int dataBlockCount;
    private int dataBlockPos;
    // Checksum
    private byte[] checksumBlock;
    // Tag[1..TAGLEN]
    private byte[] tagBlock;
    private OCBHash ocbHash;
    private boolean decrypting;

    // additional variables for save/restore calls
    private byte[] offsetBlockSave;
    private byte[] checksumBlockSave;
    private byte[] dataBlockSave;
    private int dataBlockPosSave;
    private int dataBlockCountSave;

    OCBCipherBlock(SymmetricCipher embeddedCipher) {
        super(embeddedCipher);
    }

    @Override
    String getFeedback() {
        return "OCB";
    }

    @Override
    void save() {
        offsetBlockSave = Arrays.copyOf(offsetBlock, offsetBlock.length);
        checksumBlockSave = Arrays.copyOf(checksumBlock, checksumBlock.length);
        dataBlockSave = Arrays.copyOf(dataBlock, dataBlock.length);
        dataBlockPosSave = dataBlockPos;
        dataBlockCountSave = dataBlockCount;
        ocbHash.save();
    }

    @Override
    void restore() {
        System.arraycopy(offsetBlockSave, 0, offsetBlock, 0, offsetBlock.length);
        System.arraycopy(checksumBlockSave, 0, checksumBlock, 0, checksumBlock.length);
        System.arraycopy(dataBlockSave, 0, dataBlock, 0, dataBlock.length);
        dataBlockPos = dataBlockPosSave;
        dataBlockCount = dataBlockCountSave;
        ocbHash.restore();
    }

    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv, int tagLen)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        getEmbeddedCipher().init(decrypting, algorithm, key);
        this.decrypting = decrypting;
        this.tagLen = tagLen;
        this.iv = iv.clone();

        // L_*
        this.l_sterisk = new byte[blockSize];
        getEmbeddedCipher().encryptBlock(l_sterisk, 0, this.l_sterisk, 0);

        // L_$
        this.l_dollar = OCBHash.ocb_double(l_sterisk);

        // L_0
        this.l_0 = OCBHash.ocb_double(l_dollar);

        // L_i
        this.l = new ArrayList<>();
        this.l.add(l_0);

        // Offset
        this.offset_0 = getOffsetBlock0(iv, tagLen);
        this.offsetBlock = new byte[offset_0.length];
        System.arraycopy(offset_0, 0, offsetBlock, 0, offset_0.length);

        // Checksum
        this.checksumBlock = new byte[blockSize];

        // Tag
        this.tagBlock = new byte[tagLen];

        // Data block , block count , block position
        this.dataBlock = new byte[decrypting ? blockSize + tagBlock.length : blockSize];
        this.dataBlockCount = 0;
        this.dataBlockPos = 0;

        // Hash
        this.ocbHash = new OCBHash(getEmbeddedCipher());
        this.ocbHash.init(l_sterisk, l);
    }

    /**
     * Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
     * @param iv
     * @param tagLen
     * @return
     */
    private byte[] getNonce(byte[] iv, int tagLen) {
        byte[] nonce = new byte[blockSize];
        System.arraycopy(iv, 0, nonce, nonce.length - iv.length, iv.length);
        //( tagLen * 8) << 1 == tagLen << 4
        nonce[0] = (byte) (tagLen << 4);
        nonce[nonce.length - iv.length - 1] |= 1;
        return nonce;
    }

    /**
     * Nonce-dependent and per-encryption variables
     * Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
     * bottom = str2num(Nonce[123..128])
     * Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
     * Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
     * Offset_0 = Stretch[1+bottom..128+bottom]
     * Checksum_0 = zeros(128)
     * @param iv
     * @param tagLen
     * @return
     */
    private byte[] getOffsetBlock0(byte[] iv, int tagLen) {
        // Nonce
        byte[] nonce = getNonce(iv, tagLen);

        // bottom
        int bottom = nonce[nonce.length - 1] & 0x3F;

        // Ktop
        byte[] ktopBlock = new byte[blockSize];
        nonce[nonce.length - 1] &= (byte) 0xC0;
        getEmbeddedCipher().encryptBlock(nonce, 0, ktopBlock, 0);

        // Stretch
        byte[] stretchBlock = new byte[blockSize + 8];
        System.arraycopy(ktopBlock, 0, stretchBlock, 0, ktopBlock.length);
        for (int i = 0; i < 8; ++i) {
            stretchBlock[ktopBlock.length + i] = (byte) (ktopBlock[i] ^ ktopBlock[i + 1]);
        }

        // Offset
        byte[] offsetBlock = new byte[blockSize];
        int bits = bottom % 8;
        int numBytes = bottom / 8;
        if (bits == 0) {
            System.arraycopy(stretchBlock, numBytes, offsetBlock, 0, blockSize);
        } else {
            for (int i = 0; i < blockSize; ++i) {
                int b1 = stretchBlock[numBytes] & 0xff;
                int b2 = stretchBlock[++numBytes] & 0xff;
                offsetBlock[i] = (byte) ((b1 << bits) | (b2 >>> (8 - bits)));
            }
        }
        return offsetBlock;
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(decrypting, algorithm, key, iv, DEFAULT_TAG_LEN);
    }

    @Override
    void reset() {
        // Offset
        System.arraycopy(offset_0, 0, offsetBlock, 0, offset_0.length);

        // Checksum
        Arrays.fill(checksumBlock, (byte) 0);

        // Tag
        Arrays.fill(tagBlock, (byte) 0);

        // Data
        Arrays.fill(dataBlock, (byte) 0);
        dataBlockPos = 0;
        dataBlockCount = 0;

        // Hash
        ocbHash.reset();
    }

    @Override
    void updateAAD(byte[] src, int offset, int len) {
        ocbHash.update(src, offset, len);
    }

    @Override
    int encrypt(byte[] plain, int plainOffset, int plainLen, byte[] cipher, int cipherOffset) {
        return processPlainTextBlock(plain, plainOffset, plainLen, cipher, cipherOffset);
    }

    @Override
    int decrypt(byte[] cipher, int cipherOffset, int cipherLen, byte[] plain, int plainOffset) {
        return processCipherTextBlock(cipher, cipherOffset, cipherLen, plain, plainOffset);
    }

    @Override
    int encryptFinal(byte[] plain, int plainOffset, int plainLen, byte[] cipher, int cipherOffset)
            throws IllegalBlockSizeException, ShortBufferException {
        int length = processPlainTextBlock(plain, plainOffset, plainLen, cipher, cipherOffset);
        length += processPlainTextFinal(cipher, cipherOffset + length);
        System.arraycopy(tagBlock, 0, cipher, cipherOffset + length, tagBlock.length);
        length += tagBlock.length;
        return length;
    }

    @Override
    int decryptFinal(byte[] cipher, int cipherOffset, int cipherLen, byte[] plain, int plainOffset)
            throws IllegalBlockSizeException, AEADBadTagException, ShortBufferException {
        int length = processCipherTextBlock(cipher, cipherOffset, cipherLen, plain, plainOffset);
        length += processCipherTextFinal(plain, plainOffset + length);
        return length;
    }

    private int processPlainTextBlock(byte[] plain, int plainOffset, int plainLen,
                                      byte[] cipher, int cipherOffset) {
        // Process any whole blocks
        int len = 0;
        for (int i = 0; i < plainLen; i++) {
            dataBlock[dataBlockPos++] = plain[plainOffset + i];
            if (dataBlockPos == dataBlock.length) {
                len += processPlainTextBlock(cipher, cipherOffset + len);
            }
        }
        return len;
    }

    private int processPlainTextBlock(byte[] cipher, int cipherOffset) {
        ++dataBlockCount;

        // Checksum_i = Checksum_{i-1} xor P_i
        OCBHash.xor(checksumBlock, dataBlock);

        // Offset_i = Offset_{i-1} xor L_{ntz(i)}
        byte[] lSub = OCBHash.getLSub(l, OCBHash.ocb_ntz(dataBlockCount));
        OCBHash.xor(offsetBlock, lSub);

        // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
        OCBHash.xor(dataBlock, offsetBlock);
        getEmbeddedCipher().encryptBlock(dataBlock, 0, dataBlock, 0);
        OCBHash.xor(dataBlock, offsetBlock);
        System.arraycopy(dataBlock, 0, cipher, cipherOffset, dataBlock.length);

        dataBlockPos = 0;
        return dataBlock.length;
    }

    private int processPlainTextFinal(byte[] cipher, int cipherOffset) {
        if (dataBlockPos > 0) {
            // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            OCBHash.ocb_extend(dataBlock, dataBlockPos);
            OCBHash.xor(checksumBlock, dataBlock);

            //Offset_* = Offset_m xor L_*
            OCBHash.xor(offsetBlock, l_sterisk);

            // Pad = ENCIPHER(K, Offset_*)
            byte[] pad = new byte[blockSize];
            getEmbeddedCipher().encryptBlock(offsetBlock, 0, pad, 0);

            // C_* = P_* xor Pad[1..bitlen(P_*)]
            OCBHash.xor(dataBlock, pad);
            System.arraycopy(dataBlock, 0, cipher, cipherOffset, dataBlockPos);
        }

        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
        OCBHash.xor(checksumBlock, offsetBlock);
        OCBHash.xor(checksumBlock, l_dollar);
        getEmbeddedCipher().encryptBlock(checksumBlock, 0, checksumBlock, 0);
        byte[] hashBlock = ocbHash.digest();
        OCBHash.xor(checksumBlock, hashBlock);

        System.arraycopy(checksumBlock, 0, tagBlock, 0, tagBlock.length);
        return dataBlockPos;
    }

    private int processCipherTextBlock(byte[] cipher, int cipherOffset, int cipherLen,
                                       byte[] plain, int plainOffset) {
        // Process any whole blocks
        int len = 0;
        for (int i = 0; i < cipherLen; i++) {
            dataBlock[dataBlockPos++] = cipher[cipherOffset + i];
            if (dataBlockPos == dataBlock.length) {
                len += processCipherTextBlock(plain, plainOffset + len);
            }
        }
        return len;
    }

    private int processCipherTextBlock(byte[] plain, int plainOffset) {
        ++dataBlockCount;

        // Offset_i = Offset_{i-1} xor L_{ntz(i)}
        byte[] lSub = OCBHash.getLSub(l, OCBHash.ocb_ntz(dataBlockCount));
        OCBHash.xor(offsetBlock, lSub);

        // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
        OCBHash.xor(dataBlock, offsetBlock);
        getEmbeddedCipher().decryptBlock(dataBlock, 0, dataBlock, 0);
        OCBHash.xor(dataBlock, offsetBlock);
        System.arraycopy(dataBlock, 0, plain, plainOffset, blockSize);

        // Checksum_i = Checksum_{i-1} xor P_i
        OCBHash.xor(checksumBlock, dataBlock);

        System.arraycopy(dataBlock, blockSize, dataBlock, 0, tagBlock.length);
        dataBlockPos = tagBlock.length;
        return blockSize;
    }

    private int processCipherTextFinal(byte[] plain, int plainOffset)
            throws ShortBufferException, AEADBadTagException {
        if (dataBlockPos < tagBlock.length) {
            throw new ShortBufferException("plain buffer is too small");
        }
        dataBlockPos -= tagBlock.length;
        // input Tag
        byte[] inputTagBlock = new byte[tagBlock.length];
        System.arraycopy(dataBlock, dataBlockPos, inputTagBlock, 0, inputTagBlock.length);

        if (dataBlockPos > 0) {
            // Offset_* = Offset_m xor L_*
            OCBHash.xor(offsetBlock, l_sterisk);
            // Pad = ENCIPHER(K, Offset_*)
            byte[] pad = new byte[blockSize];
            getEmbeddedCipher().encryptBlock(offsetBlock, 0, pad, 0);

            // P_* = C_* xor Pad[1..bitlen(C_*)]
            OCBHash.xor(dataBlock, pad);
            System.arraycopy(dataBlock, 0, plain, plainOffset, dataBlockPos);

            // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            OCBHash.ocb_extend(dataBlock, dataBlockPos);
            OCBHash.xor(checksumBlock, dataBlock);
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        OCBHash.xor(checksumBlock, offsetBlock);
        OCBHash.xor(checksumBlock, l_dollar);
        getEmbeddedCipher().encryptBlock(checksumBlock, 0, checksumBlock, 0);
        byte[] hashBlock = ocbHash.digest();
        OCBHash.xor(checksumBlock, hashBlock);

        System.arraycopy(checksumBlock, 0, tagBlock, 0, tagBlock.length);

        if (!Arrays.equals(inputTagBlock, tagBlock)) {
           throw new AEADBadTagException("mac check in OCB failed");
        }

        return dataBlockPos;
    }

    public int getTagLen() {
        return tagLen;
    }

    @Override
    int getBufferedLength() {
        if (decrypting) {
            return dataBlockPos;
        }
        return  0;
    }
}
