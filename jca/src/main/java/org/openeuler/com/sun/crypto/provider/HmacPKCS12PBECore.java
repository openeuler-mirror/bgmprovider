/*
 * Copyright (c) 2003, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.com.sun.crypto.provider;

import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

abstract class HmacPKCS12PBECore extends MacSpi implements Cloneable {
    private final String kdfAlgorithm;
    private final String hashAlgorithm;
    private final int blockLength;
    private Mac mac;

    HmacPKCS12PBECore(String kdfAlgorithm, String hashAlgorithm, int blockLength) throws NoSuchAlgorithmException {
        this.kdfAlgorithm = kdfAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.blockLength = blockLength;
        this.mac = Mac.getInstance(kdfAlgorithm);
    }

    @Override
    protected int engineGetMacLength() {
        return mac.getMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        char[] passwdChars;
        byte[] salt = null;
        int iCount = 0;
        if (key instanceof javax.crypto.interfaces.PBEKey) {
            javax.crypto.interfaces.PBEKey pbeKey =
                    (javax.crypto.interfaces.PBEKey) key;
            passwdChars = pbeKey.getPassword();
            salt = pbeKey.getSalt(); // maybe null if unspecified
            iCount = pbeKey.getIterationCount(); // maybe 0 if unspecified
        } else if (key instanceof SecretKey) {
            byte[] passwdBytes;
            if (!(key.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) ||
                    (passwdBytes = key.getEncoded()) == null) {
                throw new InvalidKeyException("Missing password");
            }
            passwdChars = new char[passwdBytes.length];
            for (int i = 0; i < passwdChars.length; i++) {
                passwdChars[i] = (char) (passwdBytes[i] & 0x7f);
            }
            Arrays.fill(passwdBytes, (byte) 0x00);
        } else {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        try {
            if (params == null) {
                // should not auto-generate default values since current
                // javax.crypto.Mac api does not have any method for caller to
                // retrieve the generated defaults.
                if ((salt == null) || (iCount == 0)) {
                    throw new InvalidAlgorithmParameterException
                            ("PBEParameterSpec required for salt and iteration count");
                }
            } else if (!(params instanceof PBEParameterSpec)) {
                throw new InvalidAlgorithmParameterException
                        ("PBEParameterSpec type required");
            } else {
                PBEParameterSpec pbeParams = (PBEParameterSpec) params;
                // make sure the parameter values are consistent
                if (salt != null) {
                    if (!Arrays.equals(salt, pbeParams.getSalt())) {
                        throw new InvalidAlgorithmParameterException
                                ("Inconsistent value of salt between key and params");
                    }
                } else {
                    salt = pbeParams.getSalt();
                }
                if (iCount != 0) {
                    if (iCount != pbeParams.getIterationCount()) {
                        throw new InvalidAlgorithmParameterException
                                ("Different iteration count between key and params");
                    }
                } else {
                    iCount = pbeParams.getIterationCount();
                }
            }
            // For security purpose, we need to enforce a minimum length
            // for salt; just require the minimum salt length to be 8-byte
            // which is what PKCS#5 recommends and openssl does.
            if (salt.length < 8) {
                throw new InvalidAlgorithmParameterException
                        ("Salt must be at least 8 bytes long");
            }
            if (iCount <= 0) {
                throw new InvalidAlgorithmParameterException
                        ("IterationCount must be a positive number");
            }

            byte[] derivedKey = derive(passwdChars, salt, iCount, engineGetMacLength(),
                    3, hashAlgorithm, blockLength);
            mac.init(new SecretKeySpec(derivedKey, kdfAlgorithm));
        } finally {
            Arrays.fill(passwdChars, '\0');
        }

    }

    // Uses supplied hash algorithm
    static byte[] derive(char[] chars, byte[] salt, int ic, int n, int type,
                         String hashAlgo, int blockLength) {

        // Add in trailing NULL terminator.  Special case:
        // no terminator if password is "\0".
        int length = chars.length * 2;
        if (length == 2 && chars[0] == 0) {
            chars = new char[0];
            length = 0;
        } else {
            length += 2;
        }

        byte[] passwd = new byte[length];
        for (int i = 0, j = 0; i < chars.length; i++, j += 2) {
            passwd[j] = (byte) ((chars[i] >>> 8) & 0xFF);
            passwd[j + 1] = (byte) (chars[i] & 0xFF);
        }
        byte[] key = new byte[n];

        try {
            MessageDigest sha = MessageDigest.getInstance(hashAlgo);

            int v = blockLength;
            int u = sha.getDigestLength();
            int c = roundup(n, u) / u;
            byte[] D = new byte[v];
            int s = roundup(salt.length, v);
            int p = roundup(passwd.length, v);
            byte[] I = new byte[s + p];

            Arrays.fill(D, (byte) type);
            concat(salt, I, 0, s);
            concat(passwd, I, s, p);
            Arrays.fill(passwd, (byte) 0x00);

            byte[] Ai;
            byte[] B = new byte[v];
            byte[] tmp = new byte[v];

            int i = 0;
            for (; ; i++, n -= u) {
                sha.update(D);
                sha.update(I);
                Ai = sha.digest();
                for (int r = 1; r < ic; r++)
                    Ai = sha.digest(Ai);
                System.arraycopy(Ai, 0, key, u * i, Math.min(n, u));
                if (i + 1 == c)
                    break;
                concat(Ai, B, 0, B.length);
                BigInteger B1;
                B1 = new BigInteger(1, B).add(BigInteger.ONE);

                for (int j = 0; j < I.length; j += v) {
                    BigInteger Ij;
                    int trunc;

                    if (tmp.length != v)
                        tmp = new byte[v];
                    System.arraycopy(I, j, tmp, 0, v);
                    Ij = new BigInteger(1, tmp);
                    Ij = Ij.add(B1);
                    tmp = Ij.toByteArray();
                    trunc = tmp.length - v;
                    if (trunc >= 0) {
                        System.arraycopy(tmp, trunc, I, j, v);
                    } else if (trunc < 0) {
                        Arrays.fill(I, j, j + (-trunc), (byte) 0);
                        System.arraycopy(tmp, 0, I, j + (-trunc), tmp.length);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("internal error: " + e);
        }
        return key;
    }

    private static int roundup(int x, int y) {
        return ((x + (y - 1)) / y) * y;
    }

    private static void concat(byte[] src, byte[] dst, int start, int len) {
        if (src.length == 0) {
            return;
        }
        int loop = len / src.length;
        int off, i;
        for (i = 0, off = 0; i < loop; i++, off += src.length)
            System.arraycopy(src, 0, dst, off + start, src.length);
        System.arraycopy(src, 0, dst, off + start, len - off);
    }

    @Override
    protected void engineUpdate(byte input) {
        mac.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        mac.update(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        return mac.doFinal();
    }

    @Override
    protected void engineReset() {
        mac.reset();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        HmacPKCS12PBECore hmacPKCS12PBECore = (HmacPKCS12PBECore) super.clone();
        hmacPKCS12PBECore.mac = (Mac) mac.clone();
        return hmacPKCS12PBECore;
    }

    public static final class HmacPKCS12PBESM3 extends HmacPKCS12PBECore {
        public HmacPKCS12PBESM3() throws NoSuchAlgorithmException {
            super("HmacSM3", "SM3", 64);
        }
    }
}
