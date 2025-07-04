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

package org.openeuler.sdf.jca.pbkdf;

import org.openeuler.sdf.wrapper.SDFPBKDF2Native;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;

final class SDFPBKDF2KeyImpl implements javax.crypto.interfaces.PBEKey {
    private static final long serialVersionUID = -1234868909660948157L;

    private char[] passwd;
    private final byte[] salt;
    private final int iterCount;
    private byte[] key;
    private String digestAlgo;
    private String algorithm;

    private static byte[] getPasswordBytes(char[] passwd) {
        Charset utf8 = Charset.forName("UTF-8");
        CharBuffer cb = CharBuffer.wrap(passwd);
        ByteBuffer bb = utf8.encode(cb);

        int len = bb.limit();
        byte[] passwdBytes = new byte[len];
        bb.get(passwdBytes, 0, len);

        return passwdBytes;
    }

    SDFPBKDF2KeyImpl(PBEKeySpec keySpec, String digestAlgo)
            throws InvalidKeySpecException {
        char[] passwd = keySpec.getPassword();
        if (passwd == null) {
            // Should allow an empty password.
            this.passwd = new char[0];
        } else {
            this.passwd = passwd.clone();
        }
        // remove local copy
        if (passwd != null) {
            Arrays.fill(passwd, '\0');
        }

        this.salt = keySpec.getSalt();
        if (salt == null) {
            throw new InvalidKeySpecException("Salt not found");
        }
        this.iterCount = keySpec.getIterationCount();
        if (iterCount == 0) {
            throw new InvalidKeySpecException("Iteration count not found");
        } else if (iterCount < 0) {
            throw new InvalidKeySpecException("Iteration count is negative");
        }
        int keyLength = keySpec.getKeyLength();
        if (keyLength == 0) {
            throw new InvalidKeySpecException("Key length not found");
        } else if (keyLength < 0) {
            throw new InvalidKeySpecException("Key length is negative");
        }
        this.digestAlgo = digestAlgo;
        this.algorithm = "PBKDF2WithHmac" + digestAlgo.replaceAll("-", "");

        // Convert the password from char[] to byte[]
        byte[] passwdBytes = getPasswordBytes(this.passwd);
        try {
            this.key = SDFPBKDF2Native.nativeDeriveKey(
                    digestAlgo,
                    passwdBytes,
                    salt,
                    iterCount,
                    keyLength/8
            );
        } finally {
            Arrays.fill(passwdBytes, (byte) 0);
        }
    }

    @Override
    public synchronized char[] getPassword() {
        return passwd.clone();
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    public int getIterationCount() {
        return 0;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        int retval = 0;
        for (int i = 1; i < this.key.length; i++) {
            retval += this.key[i] * i;
        }
        return(retval ^= getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode());
    }

    public boolean equals(Object obj) {
        if (obj == this)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        SecretKey that = (SecretKey) obj;

        if (!(that.getAlgorithm().equalsIgnoreCase(getAlgorithm())))
            return false;
        if (!(that.getFormat().equalsIgnoreCase("RAW")))
            return false;
        byte[] thatEncoded = that.getEncoded();
        boolean ret = MessageDigest.isEqual(key, thatEncoded);
        Arrays.fill(thatEncoded, (byte)0x00);
        return ret;
    }

    /**
     * Replace the PBE key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws ObjectStreamException if a new object representing
     * this PBE key could not be created
     */
    private Object writeReplace() throws ObjectStreamException {
        return new KeyRep(KeyRep.Type.SECRET, getAlgorithm(),
                getFormat(), getEncoded());
    }

    /**
     * Ensures that the password bytes of this key are
     * erased when there are no more references to it.
     */
    protected void finalize() throws Throwable {
        try {
            synchronized (this) {
                if (this.passwd != null) {
                    java.util.Arrays.fill(this.passwd, '\0');
                    this.passwd = null;
                }
                if (this.key != null) {
                    java.util.Arrays.fill(this.key, (byte)0x00);
                    this.key = null;
                }
            }
        } finally {
            super.finalize();
        }
    }

    /**
     * Restores the state of this object from the stream.
     * <p>
     * Deserialization of this class is not supported.
     *
     * @param  stream the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(ObjectInputStream stream)
            throws IOException, ClassNotFoundException {
        throw new InvalidObjectException(
                "PBKDF2KeyImpl keys are not directly deserializable");
    }
}
