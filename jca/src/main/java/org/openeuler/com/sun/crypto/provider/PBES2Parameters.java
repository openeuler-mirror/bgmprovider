/*
 * Copyright (c) 2012, 2018, Oracle and/or its affiliates. All rights reserved.
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

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import sun.security.util.*;

import static org.openeuler.adaptor.ObjectIdentifierHandler.newObjectIdentifier;

/**
 * This class implements the parameter set used with GM password-based
 * encryption scheme 2 (PBES2), which is defined in
 * <a href="http://www.gmbz.org.cn/main/viewfile/20210627115429111346.html">GM/T 0091-2020</a>.
 */
abstract class PBES2Parameters extends AlgorithmParametersSpi {
    private static final int HMAC_WITH_SM3[] = {1, 2, 156, 10197, 1, 401, 2};
    private static final int SM4_128_ECB[] = {1, 2, 156, 10197, 1, 104, 1};
    private static final int SM4_128_CBC[] = {1, 2, 156, 10197, 1, 104, 2};

    // OID defined by GM/T 0091-2020.
    private static final int GMT_0091_2020_PBKDF2[] = {1, 2, 156, 10197, 6, 1, 4, 1, 5, 1};
    private static final int GMT_0091_2020_HMAC_WITH_SM3[] = {1, 2, 156, 10197, 1, 401, 3, 1};
    private static final int GMT_0091_2020_SM4_128_CBC[] = {1, 2, 156, 10197, 6, 1, 4, 1, 12, 1, 1};

    private static ObjectIdentifier HMAC_WITH_SM3_OID;
    private static ObjectIdentifier SM4_128_ECB_OID;
    private static ObjectIdentifier SM4_128_CBC_OID;

    private static ObjectIdentifier GMT_0091_2020_PBKDF2_OID;
    private static ObjectIdentifier GMT_0091_2020_HMAC_WITH_SM3_OID;
    private static ObjectIdentifier GMT_0091_2020_SM4_128_CBC_OID;

    static {
        try {
            HMAC_WITH_SM3_OID = newObjectIdentifier(HMAC_WITH_SM3);
            SM4_128_ECB_OID = newObjectIdentifier(SM4_128_ECB);
            SM4_128_CBC_OID = newObjectIdentifier(SM4_128_CBC);

            GMT_0091_2020_PBKDF2_OID = newObjectIdentifier(GMT_0091_2020_PBKDF2);
            GMT_0091_2020_HMAC_WITH_SM3_OID = newObjectIdentifier(GMT_0091_2020_HMAC_WITH_SM3);
            GMT_0091_2020_SM4_128_CBC_OID = newObjectIdentifier(GMT_0091_2020_SM4_128_CBC);
        } catch (IOException ioe) {
            // should not happen
        }
    }

    private static Set<ObjectIdentifier> SM4_CBC_OID_SET = new HashSet<>(
            Arrays.asList(SM4_128_CBC_OID, GMT_0091_2020_SM4_128_CBC_OID));

    private static Set<ObjectIdentifier> HMAC_WITH_SM3_OID_SET = new HashSet<>(
            Arrays.asList(HMAC_WITH_SM3_OID, GMT_0091_2020_HMAC_WITH_SM3_OID));


    // the PBES2 algorithm name
    private String pbes2AlgorithmName = null;

    // the salt
    private byte[] salt = null;

    // the iteration count
    private int iCount = 0;

    // the cipher parameter
    private AlgorithmParameterSpec cipherParam = null;

    // the key derivation function (default is HmacSM3)
    private ObjectIdentifier kdfAlgo_OID = HMAC_WITH_SM3_OID;

    // the encryption function
    private ObjectIdentifier cipherAlgo_OID = null;

    // the cipher keysize (in bits)
    private int keysize = -1;

    private String mode;

    private String padding;

    PBES2Parameters() {
        // KDF, encryption & keysize values are set later, in engineInit(byte[])
    }

    PBES2Parameters(String pbes2AlgorithmName) throws NoSuchAlgorithmException {
        this(pbes2AlgorithmName, null, null);
    }

    PBES2Parameters(String pbes2AlgorithmName, String mode, String padding)
            throws NoSuchAlgorithmException {
        this.mode = mode;
        this.padding = padding;
        int and;
        String kdfAlgo = null;
        String cipherAlgo = null;

        // Extract the KDF and encryption algorithm names
        if (pbes2AlgorithmName.startsWith("PBEWith") &&
            (and = pbes2AlgorithmName.indexOf("And", 7 + 1)) > 0) {
            kdfAlgo = pbes2AlgorithmName.substring(7, and);
            cipherAlgo = pbes2AlgorithmName.substring(and + 3);

            // Check for keysize
            int underscore;
            if ((underscore = cipherAlgo.indexOf('_')) > 0) {
                int slash;
                if ((slash = cipherAlgo.indexOf('/', underscore + 1)) > 0) {
                    keysize =
                        Integer.parseInt(cipherAlgo.substring(underscore + 1,
                            slash));
                } else {
                    keysize =
                        Integer.parseInt(cipherAlgo.substring(underscore + 1));
                }
                cipherAlgo = cipherAlgo.substring(0, underscore);
            }
        } else {
            throw new NoSuchAlgorithmException("No crypto implementation for " +
                pbes2AlgorithmName);
        }
        StringBuilder algorithmBuilder = new StringBuilder(pbes2AlgorithmName);
        if (this.mode != null) {
            algorithmBuilder.append("/").append(this.mode);
        }
        if (this.padding != null) {
            algorithmBuilder.append("/").append(this.padding);
        }
        this.pbes2AlgorithmName = algorithmBuilder.toString();

        // kdfAlgo_OID
        if (!"HmacSM3".equals(kdfAlgo)) {
            throw new NoSuchAlgorithmException(
                "No crypto implementation for " + kdfAlgo);
        }
        kdfAlgo_OID = GMT_0091_2020_HMAC_WITH_SM3_OID;

        // cipherAlgo_OID
        if (!"SM4".equals(cipherAlgo)) {
            throw new NoSuchAlgorithmException("No Cipher implementation for " +
                    cipherAlgo);
        }
        if (keysize != 128) {
            throw new NoSuchAlgorithmException(
                    "No Cipher implementation for " + keysize + "-bit " +
                        cipherAlgo);
        }
        if ("ECB".equals(this.mode)) {
            cipherAlgo_OID = SM4_128_ECB_OID;
        } else if ("CBC".equals(this.mode)) {
            cipherAlgo_OID = GMT_0091_2020_SM4_128_CBC_OID;
        } else {
            throw new NoSuchAlgorithmException("No Cipher implementation for " +
                    this.mode + " " + cipherAlgo);
        }
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException
                ("Inappropriate parameter specification");
        }
        this.salt = ((PBEParameterSpec) paramSpec).getSalt().clone();
        this.iCount = ((PBEParameterSpec) paramSpec).getIterationCount();
        this.cipherParam = ((PBEParameterSpec) paramSpec).getParameterSpec();
    }

    @SuppressWarnings("deprecation")
    protected void engineInit(byte[] encoded)
        throws IOException
    {
        String kdfAlgo = null;
        String cipherAlgo = null;

        DerValue pBES2_params = new DerValue(encoded);
        if (pBES2_params.tag != DerValue.tag_Sequence) {
            throw new IOException("PBE parameter parsing error: "
                + "not an ASN.1 SEQUENCE tag");
        }
        DerValue kdf = pBES2_params.data.getDerValue();

        // Before JDK-8202837, PBES2-params was mistakenly encoded like
        // an AlgorithmId which is a sequence of its own OID and the real
        // PBES2-params. If the first DerValue is an OID instead of a
        // PBES2-KDFs (which should be a SEQUENCE), we are likely to be
        // dealing with this buggy encoding. Skip the OID and treat the
        // next DerValue as the real PBES2-params.
        if (kdf.getTag() == DerValue.tag_ObjectId) {
            pBES2_params = pBES2_params.data.getDerValue();
            kdf = pBES2_params.data.getDerValue();
        }

        kdfAlgo = parseKDF(kdf);

        if (pBES2_params.tag != DerValue.tag_Sequence) {
            throw new IOException("PBE parameter parsing error: "
                + "not an ASN.1 SEQUENCE tag");
        }
        cipherAlgo = parseES(pBES2_params.data.getDerValue());

        StringBuilder algorithmBuilder = new StringBuilder().append("PBEWith")
                .append(kdfAlgo).append("And").append(cipherAlgo);
        if (mode != null) {
            algorithmBuilder.append("/").append(mode);
        }
        if (padding != null) {
            algorithmBuilder.append("/").append(padding);
        }
        pbes2AlgorithmName = algorithmBuilder.toString();
    }

    @SuppressWarnings("deprecation")
    private String parseKDF(DerValue keyDerivationFunc) throws IOException {
        if (!GMT_0091_2020_PBKDF2_OID.equals((Object)keyDerivationFunc.data.getOID())) {
            throw new IOException("PBE parameter parsing error: "
                + "expecting the object identifier for PBKDF2");
        }
        if (keyDerivationFunc.tag != DerValue.tag_Sequence) {
            throw new IOException("PBE parameter parsing error: "
                + "not an ASN.1 SEQUENCE tag");
        }
        DerValue pBKDF2_params = keyDerivationFunc.data.getDerValue();
        if (pBKDF2_params.tag != DerValue.tag_Sequence) {
            throw new IOException("PBE parameter parsing error: "
                + "not an ASN.1 SEQUENCE tag");
        }
        DerValue specified = pBKDF2_params.data.getDerValue();
        // the 'specified' ASN.1 CHOICE for 'salt' is supported
        if (specified.tag == DerValue.tag_OctetString) {
            salt = specified.getOctetString();
        } else {
            // the 'otherSource' ASN.1 CHOICE for 'salt' is not supported
            throw new IOException("PBE parameter parsing error: "
                + "not an ASN.1 OCTET STRING tag");
        }
        iCount = pBKDF2_params.data.getInteger();

        DerValue prf = null;
        // keyLength INTEGER (1..MAX) OPTIONAL,
        if (pBKDF2_params.data.available() > 0) {
            DerValue keyLength = pBKDF2_params.data.getDerValue();
            if (keyLength.tag == DerValue.tag_Integer) {
                keysize = keyLength.getInteger() * 8; // keysize (in bits)
            } else {
                // Should be the prf
                prf = keyLength;
            }
        }
        // prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSM3
        String kdfAlgo = "HmacSM3";

        if (prf == null) {
            if (pBKDF2_params.data.available() > 0) {
                prf = pBKDF2_params.data.getDerValue();
            }
        }
        if (prf != null) {
            kdfAlgo_OID = prf.data.getOID();
            if (HMAC_WITH_SM3_OID_SET.contains(kdfAlgo_OID)) {
                kdfAlgo = "HmacSM3";
            } else {
                throw new IOException("PBE parameter parsing error: "
                        + "expecting the object identifier for a HmacSHA key "
                        + "derivation function");
            }
            if (prf.data.available() != 0) {
                // parameter is 'NULL' for all HmacSHA KDFs
                DerValue parameter = prf.data.getDerValue();
                if (parameter.tag != DerValue.tag_Null) {
                    throw new IOException("PBE parameter parsing error: "
                            + "not an ASN.1 NULL tag");
                }
            }
        }

        return kdfAlgo;
    }

    @SuppressWarnings("deprecation")
    private String parseES(DerValue encryptionScheme) throws IOException {
        String cipherAlgo = null;

        cipherAlgo_OID = encryptionScheme.data.getOID();
        if (SM4_128_ECB_OID.equals((Object)cipherAlgo_OID)) {
            cipherAlgo = "SM4_128";
            keysize = 128;
            mode = "ECB";
            padding = "PKCS5Padding";
        } else if (SM4_CBC_OID_SET.contains(cipherAlgo_OID)) {
            cipherAlgo = "SM4_128";
            // parameter is SM4-IV 'OCTET STRING (SIZE(16))'
            cipherParam =
                new IvParameterSpec(encryptionScheme.data.getOctetString());
            keysize = 128;
            mode = "CBC";
            padding = "PKCS5Padding";
        } else {
            throw new IOException("PBE parameter parsing error: "
                    + "expecting the object identifier for AES cipher");
        }

        return cipherAlgo;
    }

    protected void engineInit(byte[] encoded, String decodingMethod)
        throws IOException
    {
        engineInit(encoded);
    }

    protected <T extends AlgorithmParameterSpec>
            T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        if (PBEParameterSpec.class.isAssignableFrom(paramSpec)) {
            return paramSpec.cast(
                new PBEParameterSpec(this.salt, this.iCount, this.cipherParam));
        } else {
            throw new InvalidParameterSpecException
                ("Inappropriate parameter specification");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();

        DerOutputStream pBES2_params = new DerOutputStream();

        DerOutputStream keyDerivationFunc = new DerOutputStream();
        keyDerivationFunc.putOID(GMT_0091_2020_PBKDF2_OID);

        DerOutputStream pBKDF2_params = new DerOutputStream();
        pBKDF2_params.putOctetString(salt); // choice: 'specified OCTET STRING'
        pBKDF2_params.putInteger(iCount);

        if (keysize > 0) {
            pBKDF2_params.putInteger(keysize / 8); // derived key length (in octets)
        }

        DerOutputStream prf = new DerOutputStream();
        // algorithm is id-hmacWithSM3
        prf.putOID(kdfAlgo_OID);
        // parameters is 'NULL'
        prf.putNull();
        pBKDF2_params.write(DerValue.tag_Sequence, prf);

        keyDerivationFunc.write(DerValue.tag_Sequence, pBKDF2_params);
        pBES2_params.write(DerValue.tag_Sequence, keyDerivationFunc);

        DerOutputStream encryptionScheme = new DerOutputStream();
        // algorithm is id-aes128-CBC or id-aes256-CBC
        encryptionScheme.putOID(cipherAlgo_OID);
        // parameters is 'AES-IV ::= OCTET STRING (SIZE(16))'
        if (cipherParam != null && cipherParam instanceof IvParameterSpec) {
            encryptionScheme.putOctetString(
                ((IvParameterSpec) cipherParam).getIV());
        } else if (SM4_128_ECB_OID.equals((Object)cipherAlgo_OID)) {
            // optional
            encryptionScheme.putOctetString(new byte[0]);
        } else {
            throw new IOException("Wrong parameter type: IV expected");
        }
        pBES2_params.write(DerValue.tag_Sequence, encryptionScheme);

        out.write(DerValue.tag_Sequence, pBES2_params);

        return out.toByteArray();
    }

    protected byte[] engineGetEncoded(String encodingMethod)
        throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     *
     * The algorithn name pattern is: "PBEWith<prf>And<encryption>"
     * where <prf> is one of: HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384,
     * or HmacSHA512, and <encryption> is AES with a keysize suffix.
     */
    protected String engineToString() {
        return pbes2AlgorithmName;
    }

    public static final class General extends PBES2Parameters {
        public General() throws NoSuchAlgorithmException {
            super();
        }
    }

    public static final class HmacSM3AndSM4_128_ECB_PKCS5Padding extends PBES2Parameters {
        public HmacSM3AndSM4_128_ECB_PKCS5Padding() throws NoSuchAlgorithmException {
            super("PBEWithHmacSM3AndSM4_128", "ECB", "PKCS5Padding");
        }
    }

    public static final class HmacSM3AndSM4_128_CBC_PKCS5Padding extends PBES2Parameters {
        public HmacSM3AndSM4_128_CBC_PKCS5Padding() throws NoSuchAlgorithmException {
            super("PBEWithHmacSM3AndSM4_128", "CBC", "PKCS5Padding");
        }
    }
}
