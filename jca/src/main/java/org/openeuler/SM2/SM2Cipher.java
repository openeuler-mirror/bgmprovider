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

package org.openeuler.SM2;

import org.openeuler.util.*;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECPoint;

/**
 * SM2 Cipher
 */
public class SM2Cipher extends GMCipherSpi {
    private static final boolean DEBUG = false;

    public SM2Cipher() throws NoSuchAlgorithmException {
        super(new DerSM2Engine());
    }

    @Override
    protected byte[] engineWrap(Key key)
            throws IllegalBlockSizeException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Cannot get an encoding of " +
                    "the key to be wrapped");
        }
        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new InvalidKeyException("The wrappedKey cannot be null or empty");
        }
        byte[] unWrappedKey;
        try {
            unWrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }
        return ConstructKeys.constructKey(unWrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    @Override
    public int engineGetOutputSize(int i) {
        throw new UnsupportedOperationException("engineGetOutputSize");
    }

    private static class DerSM2Engine extends SM2Engine {
        private boolean forEncryption;
        private final int digestLength;
        private ECDomainParameters ecDomainParameters;

        public DerSM2Engine() throws NoSuchAlgorithmException {
            this(MessageDigest.getInstance("SM3"));
        }

        public DerSM2Engine(MessageDigest digest) throws NoSuchAlgorithmException {
            super(digest, Mode.C1C3C2);
            this.digestLength = digest.getDigestLength();
        }

        @Override
        public void init(boolean forEncryption, CipherParameters param) {
            super.init(forEncryption, param);
            this.forEncryption = forEncryption;
            ECKeyParameters ecKeyParameters;
            ecKeyParameters = (ECKeyParameters) param;
            ecDomainParameters = ecKeyParameters.getParameters();
        }

        @Override
        public byte[] processBlock(byte[] in, int inOff, int inLen)
                throws InvalidCipherTextException, IOException {
            if (forEncryption) {
                return encrypt(in, inOff, inLen);
            }
            return decrypt(in, inOff, inLen);
        }

        private byte[] encrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException, IOException {
            byte[] bytes = super.processBlock(in, inOff, inLen);
            int curveLength = (ecDomainParameters.getCurve().getField().getFieldSize() + 7) / 8;

            // c1
            byte[] c1 = new byte[curveLength * 2 + 1];
            System.arraycopy(bytes, 0, c1, 0, c1.length);
            ECPoint c1Point = ECUtil.decodePoint(c1, ecDomainParameters.getCurve());

            // c2
            byte[] c2 = new byte[bytes.length - c1.length - digestLength];
            System.arraycopy(bytes, c1.length + digestLength, c2, 0, c2.length);

            // c3
            byte[] c3 = new byte[digestLength];
            System.arraycopy(bytes, c1.length, c3, 0, c3.length);

            if (DEBUG) {
                System.out.println("c1 = " + java.util.Arrays.toString(c1));
                System.out.println("c2 = " + java.util.Arrays.toString(c2));
                System.out.println("c3 = " + java.util.Arrays.toString(c3));
            }

            DerOutputStream out = new DerOutputStream();
            out.putInteger(c1Point.getAffineX());
            out.putInteger(c1Point.getAffineY());
            out.putOctetString(c3);
            out.putOctetString(c2);
            DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            try {
                return result.toByteArray();
            } catch (IOException e) {
                throw new InvalidCipherTextException("DERSequence getEncoded failed", e);
            }
        }

        private byte[] decrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException, IOException {
            byte[] bytes = new byte[inLen];
            System.arraycopy(in, inOff, bytes, 0, inLen);

            DerInputStream inDer = new DerInputStream(bytes, inOff, inLen, false);
            DerValue[] values = inDer.getSequence(2);

            // check number of components in the read sequence
            // and trailing data
            if ((values.length != 4) || (inDer.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }

            BigInteger x = values[0].getPositiveBigInteger();
            BigInteger y = values[1].getPositiveBigInteger();
            ECPoint c1Point = new ECPoint(x, y);
            byte[] c1 = ECUtil.encodePoint(c1Point, ecDomainParameters.getCurve());
            byte[] c3 = values[2].getOctetString();
            byte[] c2 = values[3].getOctetString();

            if (DEBUG) {
                System.out.println("c1 = " + java.util.Arrays.toString(c1));
                System.out.println("c2 = " + java.util.Arrays.toString(c2));
                System.out.println("c3 = " + java.util.Arrays.toString(c3));
            }

            byte[] concatenate = Util.concatenate(c1, c3, c2);
            return super.processBlock(concatenate, 0, concatenate.length);
        }
    }
}

