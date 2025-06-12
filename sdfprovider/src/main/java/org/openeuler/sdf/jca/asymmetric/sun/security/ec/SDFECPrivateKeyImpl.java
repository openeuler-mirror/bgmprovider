/*
 * Copyright (c) 2006, 2018, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jca.asymmetric.sun.security.ec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.math.BigInteger;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.util.SDFECParameters;
import sun.security.util.ArrayUtil;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.pkcs.PKCS8Key;

import static org.openeuler.sdf.commons.constant.SDFConstant.ENC_SM2_PRIVATE_KEY_SIZE;

/**
 * Key implementation for EC private keys.
 * <p>
 * ASN.1 syntax for EC private keys from SEC 1 v1.5 (draft):
 *
 * <pre>
 * EXPLICIT TAGS
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey OCTET STRING,
 *   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
 *   publicKey [1] BIT STRING OPTIONAL
 * }
 * </pre>
 *
 * We currently ignore the optional parameters and publicKey fields. We
 * require that the parameters are encoded as part of the AlgorithmIdentifier,
 * not in the private key structure.
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
public final class SDFECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey, SDFEncryptKey {

    private static final long serialVersionUID = 88695385615075129L;

    private BigInteger s;       // private value
    private byte[] arrayS;      // private value as a little-endian array
    private ECParameterSpec params;

    /* The version for this key */
    private static final int V1 = 0;
    private static final int V2 = 1;

    // use enc privateKey
    private boolean isEncKey = false;

    /**
     * Construct a key from its encoding. Called by the ECKeyFactory.
     */
    public SDFECPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {
        decode(new ByteArrayInputStream(encoded));
        parseKeyBits();
    }

    /**
     * Construct a key from its components. Used by the
     * KeyFactory.
     */
    public SDFECPrivateKeyImpl(BigInteger s, ECParameterSpec params)
            throws InvalidKeyException {
        this.s = s;
        this.params = params;
        makeEncoding(s);
    }

    SDFECPrivateKeyImpl(byte[] s, ECParameterSpec params)
            throws InvalidKeyException {
        this.arrayS = s.clone();
        this.params = params;
        makeEncoding(s);
    }

    public SDFECPrivateKeyImpl(byte[] encoded, boolean isEncKey) throws InvalidKeyException {
        this(encoded);
        this.isEncKey = isEncKey;
    }

    public SDFECPrivateKeyImpl(BigInteger s, ECParameterSpec params, boolean isEncKey)
            throws InvalidKeyException {
        this.s = s;
        this.params = params;
        this.isEncKey = isEncKey;
        makeEncoding(s);
    }

    SDFECPrivateKeyImpl(byte[] s, ECParameterSpec params, boolean isEncKey)
            throws InvalidKeyException {
        this.arrayS = s.clone();
        this.params = params;
        this.isEncKey = isEncKey;
        makeEncoding(s);
    }

    private void makeEncoding(byte[] s) throws InvalidKeyException {
        algid = new AlgorithmId
                (AlgorithmId.EC_oid, SDFECParameters.getAlgorithmParameters(params));
        try {
            DerOutputStream out = new DerOutputStream();
            out.putInteger(1); // version 1
            byte[] privBytes = s.clone();
            ArrayUtil.reverse(privBytes);
            out.putOctetString(privBytes);
            DerValue val =
                    new DerValue(DerValue.tag_Sequence, out.toByteArray());
            key = val.toByteArray();
        } catch (IOException exc) {
            // should never occur
            throw new InvalidKeyException(exc);
        }
    }

    private void makeEncoding(BigInteger s) throws InvalidKeyException {
        algid = new AlgorithmId
                (AlgorithmId.EC_oid, SDFECParameters.getAlgorithmParameters(params));
        try {
            byte[] sArr = s.toByteArray();
            // convert to fixed-length array
            int numOctets;
            if (isEncKey) {
                numOctets = ENC_SM2_PRIVATE_KEY_SIZE;
            } else {
                numOctets = (params.getOrder().bitLength() + 7) / 8;
            }
            byte[] sOctets = new byte[numOctets];
            int inPos = Math.max(sArr.length - sOctets.length, 0);
            int outPos = Math.max(sOctets.length - sArr.length, 0);
            int length = Math.min(sArr.length, sOctets.length);
            System.arraycopy(sArr, inPos, sOctets, outPos, length);

            DerOutputStream out = new DerOutputStream();
            out.putInteger(1); // version 1
            out.putOctetString(sOctets);
            DerValue val =
                    new DerValue(DerValue.tag_Sequence, out.toByteArray());
            key = val.toByteArray();
        } catch (IOException exc) {
            // should never occur
            throw new InvalidKeyException(exc);
        }
    }

    // see JCA doc
    public String getAlgorithm() {
        return "EC";
    }

    // see JCA doc
    public BigInteger getS() {
        if (s == null) {
            byte[] arrCopy = arrayS.clone();
            ArrayUtil.reverse(arrCopy);
            s = new BigInteger(1, arrCopy);
        }
        return s;
    }

    public byte[] getArrayS() {
        if (arrayS == null) {
            byte[] arr = getS().toByteArray();
            ArrayUtil.reverse(arr);
            int byteLength;
            if (isEncKey) {
                byteLength = ENC_SM2_PRIVATE_KEY_SIZE;
            } else {
                byteLength = (params.getOrder().bitLength() + 7) / 8;
            }
            arrayS = new byte[byteLength];
            int length = Math.min(byteLength, arr.length);
            System.arraycopy(arr, 0, arrayS, 0, length);
        }
        return arrayS.clone();
    }

    public boolean isEncKey() {
        return isEncKey;
    }

    // see JCA doc
    public ECParameterSpec getParams() {
        return params;
    }

    /**
     * Parse the key. Called by PKCS8Key.
     */
    protected void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(key);
            DerValue derValue = in.getDerValue();
            if (derValue.tag != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = derValue.data;
            int version = data.getInteger();
            if (version != 1) {
                throw new IOException("Version must be 1");
            }
            byte[] privData = data.getOctetString();
            ArrayUtil.reverse(privData);
            arrayS = privData;
            // enc private key
            if (arrayS.length == ENC_SM2_PRIVATE_KEY_SIZE) {
                isEncKey = true;
            }
            while (data.available() != 0) {
                DerValue value = data.getDerValue();
                if (value.isContextSpecific((byte) 0)) {
                    // ignore for now
                } else if (value.isContextSpecific((byte) 1)) {
                    // ignore for now
                } else {
                    throw new InvalidKeyException("Unexpected value: " + value);
                }
            }
            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new InvalidKeyException("EC domain parameters must be "
                        + "encoded in the algorithm identifier");
            }
            params = algParams.getParameterSpec(ECParameterSpec.class);
        } catch (IOException | InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC private key", e);
        }
    }

    /**
     * Restores the state of this object from the stream.
     * <p>
     * Deserialization of this object is not supported.
     *
     * @param  stream the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(ObjectInputStream stream)
            throws IOException, ClassNotFoundException {
        throw new InvalidObjectException(
                "ECPrivateKeyImpl keys are not directly deserializable");
    }

    public void decode(InputStream is) throws InvalidKeyException {
        try {
            DerValue val = new DerValue(is);
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("invalid key format");
            }

            int version = val.data.getInteger();
            if (version != V1 && version != V2) {
                throw new InvalidKeyException("unknown version: " + version);
            }
            algid = AlgorithmId.parse (val.data.getDerValue ());
            key = val.data.getOctetString ();
            parseKeyBits ();
            DerValue next;
            if (val.data.available() == 0) {
                return;
            }
            next = val.data.getDerValue();
            if (next.isContextSpecific((byte)0)) {
                if (val.data.available() == 0) {
                    return;
                }
                next = val.data.getDerValue();
            }

            if (next.isContextSpecific((byte)1)) {
                if (version == V1) {
                    throw new InvalidKeyException("publicKey seen in v1");
                }
                if (val.data.available() == 0) {
                    return;
                }
            }
            throw new InvalidKeyException("Extra bytes");
        } catch (IOException e) {
            throw new InvalidKeyException("IOException : " + e.getMessage());
        }
    }
}
