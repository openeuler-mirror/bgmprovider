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

import org.openeuler.util.Util;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import static org.openeuler.com.sun.crypto.provider.SM4Constants.SM4_BLOCK_SIZE;

/**
 * Counter with CBC-MAC (CCM) is a generic authenticated encryption
 * block cipher mode.  CCM is only defined for use with 128-bit block
 * ciphers.  The CCM design principles can easily be applied to other
 * block sizes, but these modes will require their own specifications.
 * https://datatracker.ietf.org/doc/html/rfc3610
 */
final class CBCMacCounterMode extends FeedbackCipher {
    static final int DEFAULT_TAG_LEN = 8;
    static final int DEFAULT_IV_LEN = 12;

    // Number of octets in authentication field
    private int M = DEFAULT_TAG_LEN;

    // Number of octets in length field
    private int L;

    private FeedbackCipher cbcFeedbackCipher;
    private FeedbackCipher ctrFeedbackCipher;

    private ByteArrayOutputStream aadBuffer = new ByteArrayOutputStream();
    private ByteArrayOutputStream dataBuffer = new ByteArrayOutputStream();

    private byte[] aadBufferSave;

    private byte[] dataBufferSave;

    private CBCMacCounterMode(SymmetricCipher embeddedCipher, FeedbackCipher cbcFeedbackCipher,
                              FeedbackCipher ctrFeedbackCipher) {
        super(embeddedCipher);
        this.cbcFeedbackCipher = cbcFeedbackCipher;
        this.ctrFeedbackCipher = ctrFeedbackCipher;
    }

    CBCMacCounterMode(SymmetricCipher embeddedCipher) {
        this(embeddedCipher, new CipherBlockChaining(embeddedCipher), new CounterMode(embeddedCipher));
    }

    @Override
    String getFeedback() {
        return "CCM";
    }

    @Override
    void save() {
        aadBufferSave = aadBuffer.toByteArray();
        dataBufferSave = dataBuffer.toByteArray();
    }

    @Override
    void restore() {
        aadBuffer.write(aadBufferSave,0, aadBufferSave.length);
        dataBuffer.write(dataBufferSave,0,dataBufferSave.length);
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(decrypting, algorithm, key, iv, DEFAULT_TAG_LEN);
    }

    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv, int tagLen)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.iv = iv.clone();
        this.M = tagLen;
        this.L = 15 - this.iv.length;

        // init cbcFeedbackCipher
        byte[] ivBytes = new byte[blockSize];
        cbcFeedbackCipher.init(decrypting, algorithm, key, ivBytes);

        // init ctrFeedbackCipher
        byte[] A0 = getA_0();
        ctrFeedbackCipher.init(decrypting, algorithm, key, A0);
    }

    @Override
    void updateAAD(byte[] src, int offset, int len) {
        if (aadBuffer != null) {
            aadBuffer.write(src, offset, len);
        } else {
            // update has already been called
            throw new IllegalStateException
                    ("Update has been called; no more AAD data");
        }
    }

    @Override
    void reset() {
        this.dataBuffer.reset();
        this.aadBuffer.reset();
        this.cbcFeedbackCipher.reset();
        this.ctrFeedbackCipher.reset();
    }

    @Override
    int encrypt(byte[] plain, int plainOffset, int plainLen, byte[] cipher, int cipherOffset) {
        update(plain, plainOffset, plainLen);
        return 0;
    }

    @Override
    int decrypt(byte[] cipher, int cipherOffset, int cipherLen, byte[] plain, int plainOffset) {
        update(cipher, cipherOffset, cipherLen);
        return 0;
    }

    void update(byte[] input, int inputOffset, int inputLen) {
        if (input == null || inputLen <= 0) {
            return;
        }
        dataBuffer.write(input, inputOffset, inputLen);
    }

    @Override
    int encryptFinal(byte[] plain, int plainOffset, int plainLen, byte[] cipher, int cipherOffset)
            throws IllegalBlockSizeException, ShortBufferException {
        encrypt(plain, plainOffset, plainLen, cipher, cipherOffset);

        byte[] dataBytes = dataBuffer.toByteArray();
        // check data length
        checkDataLength(dataBytes.length);
        byte[] X;
        try {
            X = getX(dataBytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

        /*
         * The authentication value U is computed by encrypting T with the key
         *    stream block S_0 and truncating it to the desired length.
         *       T := first-M-bytes( X_n+1 )
         *       U := T XOR first-M-bytes( S_0 )
         *
         *      Equivalent to :
         *       U := first-M-bytes ( T XOR S_0 ) = first-M-bytes (E (K , X_n+1) by CTR)
         */
        byte[] E_X = new byte[X.length];
        ctrFeedbackCipher.encrypt(X, 0, X.length, E_X, 0);
        byte[] U = new byte[M];
        System.arraycopy(E_X, 0, U, 0, U.length);

        /*
         *  The message is encrypted by XORing the octets of message m with the
         *  first l(m) octets of the concatenation of S_1, S_2, S_3, ... .  Note
         *  that S_0 is not used to encrypt the message.
         */
        int encryptLen = ctrFeedbackCipher.encrypt(dataBytes, 0, dataBytes.length, cipher, cipherOffset);

        System.arraycopy(U, 0, cipher, cipherOffset + encryptLen, U.length);
        encryptLen += U.length;

        return encryptLen;
    }

    @Override
    int decryptFinal(byte[] cipher, int cipherOffset, int cipherLen, byte[] plain, int plainOffset)
            throws IllegalBlockSizeException, AEADBadTagException, ShortBufferException {
        decrypt(cipher, cipherOffset, cipherLen, plain, plainOffset);

        byte[] cipherBytes = dataBuffer.toByteArray();
        int dataLen = cipherBytes.length - M;
        checkDataLength(dataLen);

        // decrypt U
        byte[] U = new byte[blockSize];
        System.arraycopy(cipherBytes, dataLen, U, 0, M);
        byte[] X_D = new byte[U.length];
        ctrFeedbackCipher.decrypt(U, 0, U.length, X_D, 0);

        // decrypt data
        int decryptLen = ctrFeedbackCipher.decrypt(cipherBytes, 0, dataLen, plain, plainOffset);
        byte[] dataBytes = new byte[decryptLen];
        System.arraycopy(plain, plainOffset, dataBytes, 0, dataBytes.length);

        // compute Xn+1
        byte[] X;
        try {
            X = getX(dataBytes);
        }  catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

        // check T
        checkT(X, X_D);

        return decryptLen;
    }

    private void checkT(byte[] X, byte[] X_D) throws AEADBadTagException {
        for (int i = 0; i < M; i++) {
            if (X[i] != X_D[i]) {
                throw new AEADBadTagException("mac check in CCM failed");
            }
        }
    }

    private void checkDataLength(int dataLen) throws ShortBufferException {
        if (L < 4) {
            int limitLen = 1 << (8 * L);
            if (dataLen >= limitLen) {
                throw new IllegalStateException("CCM packet too large for choice of L");
            }
        }
    }

    private byte[] getA_0() {
        return getA_i(0);
    }

    private byte[] getA_i(int num) {
        byte[] A = new byte[blockSize];
        // Flags
        A[0] = (byte) ((L - 1) & 0x7);
        // Nonce N
        System.arraycopy(iv, 0, A, 1, iv.length);
        for (int i = 0; i < num; i++) {
            increment(A);
        }
        return A;
    }

    /**
     * Increment the counter value.
     */
    private static void increment(byte[] b) {
        int n = b.length - 1;
        while ((n >= 0) && (++b[n] == 0)) {
            n--;
        }
    }

    /**
     *  X_1 := E( K, B_0 )
     *  X_i+1 := E( K, X_i XOR B_i )  for i=1, ..., n
     */
    private byte[] getX(byte[] dataBytes)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        // compute authentication B_0
        int dataLen = dataBytes.length;
        byte[] B0 = getAuthB_0(dataLen);

        // aad
        int aadLen = aadBuffer.size();
        byte[] aadLenBytes;
        if (aadLen == 0) {
            aadLenBytes = new byte[0];
        } else if (aadLen < 65280) { // 0 < l(a) < (2^16 - 2^8)
            // 0x0001 ... 0xFEFF
            aadLenBytes = new byte[2];
            Util.shortToBigEndian((short) aadLen, aadLenBytes, 0);
        } else { // (2^16 - 2^8) <= l(a) < 2^32 , can't go any higher than 2^32
            // 0xFFFE  4 octets of l(a)
            aadLenBytes = new byte[6];
            aadLenBytes[0] = (byte) 0xFF;
            aadLenBytes[1] = (byte) 0xFE;
            Util.intToBigEndian(aadLen, aadLenBytes, 2);
        }
        byte[] aadBytes = aadBuffer.toByteArray();

        byte[] cipherBytes = new byte[blockSize];

        // encrypt B0
        cbcFeedbackCipher.encrypt(B0, 0, B0.length, cipherBytes, 0);

        // encrypt aadLenBytes and addBytes
        if (aadLenBytes.length > 0) {
            int totalLen = getPaddingLen(aadLenBytes.length + aadLen, blockSize);
            byte[] newBytes = new byte[totalLen];
            System.arraycopy(aadLenBytes, 0, newBytes, 0, aadLenBytes.length);
            System.arraycopy(aadBytes, 0, newBytes, aadLenBytes.length, aadBytes.length);

            for (int plainOffset = 0; plainOffset < newBytes.length; plainOffset += blockSize) {
                cbcFeedbackCipher.encrypt(newBytes, plainOffset, blockSize, cipherBytes, 0);
            }
        }

        // encrypt dataBytes
        if (dataLen > 0) {
            int totalLen = getPaddingLen(dataLen, blockSize);
            byte[] newBytes;
            if (totalLen == dataLen) {
                newBytes = dataBytes;
            } else {
                newBytes = Arrays.copyOf(dataBytes, totalLen);
            }
            for (int plainOffset = 0; plainOffset < newBytes.length; plainOffset += blockSize) {
                cbcFeedbackCipher.encrypt(newBytes, plainOffset, blockSize, cipherBytes, 0);
            }
        }

        return cipherBytes;
    }

    private static int getPaddingLen(int len, int blockSize) {
        int newLen = len;
        if (newLen % blockSize != 0) {
            newLen = (newLen / blockSize + 1) * blockSize;
        }
        return newLen;
    }

    /**
     * The first block B_0 is formatted as follows, where l(m) is encoded in
     * most-significant-byte first order:
     * <p>
     * Octet Number   Contents
     * ------------   ---------
     * 0              Flags
     * 1 ... 15-L     Nonce N
     * 16-L ... 15    l(m)
     *
     * @return B_0
     */
    private byte[] getAuthB_0(int dataLen) {
        byte[] B = new byte[SM4_BLOCK_SIZE];
        // Flags
        B[0] = getAuthFlags();
        // Nonce N
        System.arraycopy(iv, 0, B, 1, iv.length);
        // l(m)
        int lm = dataLen;
        int count = 1;
        while (lm > 0) {
            B[B.length - count] = (byte) (lm & 0xff);
            lm >>>= 8;
            count++;
        }
        return B;
    }

    /**
     * Within the first block B_0, the Flags field is formatted as follows:
     * <p>
     * Bit Number   Contents
     * ----------   ----------------------
     * 7            Reserved (always zero)
     * 6            Adata
     * 5 ... 3      M'
     * 2 ... 0      L'
     *
     * @return
     */
    private byte getAuthFlags() {
        byte flags = 0;
        // Adata
        if (aadBuffer.size() > 0) {
            flags |= 0x40;
        }
        // M'
        flags |= (((M - 2) / 2) & 0x7) << 3;
        // L'
        flags |= (L - 1) & 0x7;
        return flags;
    }

    public int getTagLen() {
        return this.M;
    }

    @Override
    int getBufferedLength() {
        return dataBuffer.size();
    }
}
