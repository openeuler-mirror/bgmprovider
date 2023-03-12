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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

import org.openeuler.util.*;

/**
 * SM2 public key encryption engine - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
 *
 */
public class SM2Engine
{
    public enum Mode
    {
        C1C2C3, C1C3C2;
    }

    private final MessageDigest digest;
    private final Mode mode;

    private boolean forEncryption;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private SecureRandom random;

    public SM2Engine() throws NoSuchAlgorithmException {
        this(MessageDigest.getInstance("SM3"), Mode.C1C2C3);
    }

    public SM2Engine(MessageDigest digest) throws NoSuchAlgorithmException {
        this(digest, Mode.C1C2C3);
    }

    public SM2Engine(MessageDigest digest, Mode mode) throws NoSuchAlgorithmException {
        if (mode == null)
        {
            throw new IllegalArgumentException("mode cannot be NULL");
        }
        this.digest = digest;
        this.mode = mode;
    }

    public void init(boolean forEncryption, CipherParameters param)
    {
        this.forEncryption = forEncryption;

        if (forEncryption)
        {
            ecKey = (ECKeyParameters)param;
            ecParams = ecKey.getParameters();

            ECPoint s = ECUtil.multiply(((ECPublicKeyParameters)ecKey).getQ(), ecParams.getH(), ecParams.getCurve());
            if (s.equals(ECPoint.POINT_INFINITY))
            {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }

            random = new SecureRandom();
        }
        else
        {
            ecKey = (ECKeyParameters)param;
            ecParams = ecKey.getParameters();
        }

        curveLength = (ecParams.getCurve().getField().getFieldSize() + 7) / 8;
    }

    public byte[] processBlock(
            byte[] in,
            int inOff,
            int inLen)
            throws InvalidCipherTextException, IOException {
        if (forEncryption)
        {
            return encrypt(in, inOff, inLen);
        }
        else
        {
            return decrypt(in, inOff, inLen);
        }
    }

    public int getOutputSize(int inputLen)
    {
        return (1 + 2 * curveLength) + inputLen + digest.getDigestLength();
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen)
    {
        byte[] c2 = new byte[inLen];

        System.arraycopy(in, inOff, c2, 0, c2.length);

        byte[] c1;
        ECPoint kPB;
        do
        {
            BigInteger k = nextK();

            ECPoint c1P = ECUtil.multiply(ecParams.getG(), k, ecParams.getCurve());

            c1 = ECUtil.encodePoint(c1P, ecParams.getCurve());

            kPB = ECUtil.multiply(((ECPublicKeyParameters)ecKey).getQ(), k, ecParams.getCurve());

            kdf(digest, kPB, c2);
        }
        while (notEncrypted(c2, in, inOff));

        addFieldElement(digest, kPB.getAffineX());
        digest.update(in, inOff, inLen);
        addFieldElement(digest, kPB.getAffineY());

        byte[] c3 = digest.digest();

        switch (mode)
        {
            case C1C3C2:
                return Util.concatenate(c1, c3, c2);
            default:
                return Util.concatenate(c1, c2, c3);
        }
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException, IOException {
        byte[] c1 = new byte[curveLength * 2 + 1];

        System.arraycopy(in, inOff, c1, 0, c1.length);

        ECPoint c1P = ECUtil.decodePoint(c1, ecParams.getCurve());

        ECPoint s = ECUtil.multiply(c1P, ecParams.getH(), ecParams.getCurve());
        if (s.equals(ECPoint.POINT_INFINITY))
        {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        }

        c1P = ECUtil.multiply(c1P, ((ECPrivateKeyParameters)ecKey).getD(), ecParams.getCurve());

        int digestSize = this.digest.getDigestLength();
        byte[] c2 = new byte[inLen - c1.length - digestSize];

        if (mode == Mode.C1C3C2)
        {
            System.arraycopy(in, inOff + c1.length + digestSize, c2, 0, c2.length);
        }
        else
        {
            System.arraycopy(in, inOff + c1.length, c2, 0, c2.length);
        }

        kdf(digest, c1P, c2);

        addFieldElement(digest, c1P.getAffineX());
        digest.update(c2, 0, c2.length);
        addFieldElement(digest, c1P.getAffineY());

        byte[] c3 = digest.digest();

        int check = 0;
        if (mode == Mode.C1C3C2)
        {
            for (int i = 0; i != c3.length; i++)
            {
                check |= c3[i] ^ in[inOff + c1.length + i];
            }
        }
        else
        {
            for (int i = 0; i != c3.length; i++)
            {
                check |= c3[i] ^ in[inOff + c1.length + c2.length + i];
            }
        }

        java.util.Arrays.fill(c1, (byte)0);
        java.util.Arrays.fill(c3, (byte)0);

        if (check != 0)
        {
            java.util.Arrays.fill(c2, (byte)0);
            throw new InvalidCipherTextException("invalid cipher text");
        }

        return c2;
    }

    private boolean notEncrypted(byte[] encData, byte[] in, int inOff)
    {
        for (int i = 0; i != encData.length; i++)
        {
            if (encData[i] != in[inOff + i])
            {
                return false;
            }
        }

        return true;
    }

    private void kdf(MessageDigest digest, ECPoint c1, byte[] encData)
    {
        int digestSize = digest.getDigestLength();
        byte[] buf = new byte[Math.max(4, digestSize)];
        int off = 0;
        int ct = 0;

        while (off < encData.length)
        {
            addFieldElement(digest, c1.getAffineX());
            addFieldElement(digest, c1.getAffineY());

            Util.intToBigEndian(++ct, buf, 0);
            digest.update(buf, 0, 4);
            byte[] res = digest.digest();

            int xorLen = Math.min(digestSize, encData.length - off);
            xor(encData, res, off, xorLen);
            off += xorLen;
        }
    }

    private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining)
    {
        for (int i = 0; i != dRemaining; i++)
        {
            data[dOff + i] ^= kdfOut[i];
        }
    }

    private BigInteger nextK()
    {
        int qBitLength = ecParams.getN().bitLength();

        BigInteger k;
        do
        {
            k = Util.createRandomBigInteger(qBitLength, random);
        }
        while (k.equals(Util.ZERO) || k.compareTo(ecParams.getN()) >= 0);

        return k;
    }

    private void addFieldElement(MessageDigest digest, BigInteger v)
    {
        byte[] p = Util.asUnsignedByteArray(curveLength, v);

        digest.update(p, 0, p.length);
    }
}

