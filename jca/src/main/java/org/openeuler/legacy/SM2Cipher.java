/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.legacy;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.GMCipherSpi;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.openeuler.ConstructKeys;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

/**
 * SM2 Cipher
 */
public class SM2Cipher extends GMCipherSpi {
    private static final boolean DEBUG = false;

    public SM2Cipher() {
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

        public DerSM2Engine() {
            this(new SM3Digest());
        }

        public DerSM2Engine(Digest digest) {
            super(digest, Mode.C1C3C2);
            this.digestLength = digest.getDigestSize();
        }

        @Override
        public void init(boolean forEncryption, CipherParameters param) {
            super.init(forEncryption, param);
            this.forEncryption = forEncryption;
            ECKeyParameters ecKeyParameters;
            if (this.forEncryption) {
                ParametersWithRandom rParam = (ParametersWithRandom) param;
                ecKeyParameters = (ECKeyParameters) rParam.getParameters();
            } else {
                ecKeyParameters = (ECKeyParameters) param;
            }
            ecDomainParameters = ecKeyParameters.getParameters();
        }

        @Override
        public byte[] processBlock(byte[] in, int inOff, int inLen)
                throws InvalidCipherTextException {
            if (forEncryption) {
                return encrypt(in, inOff, inLen);
            }
            return decrypt(in, inOff, inLen);
        }

        private byte[] encrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
            byte[] bytes = super.processBlock(in, inOff, inLen);
            int curveLength = (ecDomainParameters.getCurve().getFieldSize() + 7) / 8;

            // c1
            byte[] c1 = new byte[curveLength * 2 + 1];
            System.arraycopy(bytes, 0, c1, 0, c1.length);
            ECPoint c1Point = ecDomainParameters.getCurve().decodePoint(c1);

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

            DERSequence derSequence = new DERSequence(new ASN1Encodable[]{
                    new ASN1Integer(c1Point.getAffineXCoord().toBigInteger()),
                    new ASN1Integer(c1Point.getAffineYCoord().toBigInteger()),
                    new DEROctetString(c3),
                    new DEROctetString(c2)
            });
            try {
                return derSequence.getEncoded();
            } catch (IOException e) {
                throw new InvalidCipherTextException("DERSequence getEncoded failed", e);
            }
        }

        private byte[] decrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
            byte[] bytes = new byte[inLen];
            System.arraycopy(in, inOff, bytes, 0, inLen);
            ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(bytes);
            check(asn1Sequence);
            BigInteger x = ((ASN1Integer) asn1Sequence.getObjectAt(0)).getPositiveValue();
            BigInteger y = ((ASN1Integer) asn1Sequence.getObjectAt(1)).getPositiveValue();
            ECPoint c1Point = ecDomainParameters.getCurve().createPoint(x, y);
            byte[] c1 = c1Point.getEncoded(false);
            byte[] c2 = ((ASN1OctetString) asn1Sequence.getObjectAt(3)).getOctets();
            byte[] c3 = ((ASN1OctetString) asn1Sequence.getObjectAt(2)).getOctets();

            if (DEBUG) {
                System.out.println("c1 = " + java.util.Arrays.toString(c1));
                System.out.println("c2 = " + java.util.Arrays.toString(c2));
                System.out.println("c3 = " + java.util.Arrays.toString(c3));
            }

            byte[] concatenate = Arrays.concatenate(c1, c3, c2);
            return super.processBlock(concatenate, 0, concatenate.length);
        }

        private void check(ASN1Sequence asn1Sequence) throws InvalidCipherTextException {
            if (asn1Sequence.size() != 4) {
                throw new InvalidCipherTextException("ASN1Sequence size is not equal 4");
            }
            if (!(asn1Sequence.getObjectAt(0) instanceof ASN1Integer)) {
                throw new InvalidCipherTextException("The c1.x object type is not ASN1Integer");
            }
            if (!(asn1Sequence.getObjectAt(1) instanceof ASN1Integer)) {
                throw new InvalidCipherTextException("The c1.y object type is not ASN1Integer");
            }
            if (!(asn1Sequence.getObjectAt(2) instanceof ASN1OctetString)) {
                throw new InvalidCipherTextException("The c3 object type is not ASN1OctetString");
            }
            if (!(asn1Sequence.getObjectAt(3) instanceof ASN1OctetString)) {
                throw new InvalidCipherTextException("The c2 object type is not ASN1OctetString");
            }
        }
    }
}
