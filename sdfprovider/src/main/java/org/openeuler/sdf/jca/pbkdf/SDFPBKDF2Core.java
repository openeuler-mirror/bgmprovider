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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

abstract class SDFPBKDF2Core extends SecretKeyFactorySpi {
    private final String digestAlgo;

    SDFPBKDF2Core(String digestAlgo) {
        this.digestAlgo = digestAlgo;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec)
            throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("Invalid key spec");
        }
        PBEKeySpec ks = (PBEKeySpec) keySpec;
        return new SDFPBKDF2KeyImpl(ks, digestAlgo);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecCl)
            throws InvalidKeySpecException {
        if (key instanceof javax.crypto.interfaces.PBEKey) {
            // Check if requested key spec is amongst the valid ones
            if ((keySpecCl != null)
                    && PBEKeySpec.class.isAssignableFrom(keySpecCl)) {
                javax.crypto.interfaces.PBEKey pKey =
                        (javax.crypto.interfaces.PBEKey) key;
                return new PBEKeySpec
                        (pKey.getPassword(), pKey.getSalt(),
                                pKey.getIterationCount(), pKey.getEncoded().length*8);
            } else {
                throw new InvalidKeySpecException("Invalid key spec");
            }
        } else {
            throw new InvalidKeySpecException("Invalid key " +
                    "format/algorithm");
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key)
            throws InvalidKeyException {
        if ((key != null) &&
                (key.getAlgorithm().equalsIgnoreCase("PBKDF2WithHmac" + digestAlgo.replaceAll("-", ""))) &&
                (key.getFormat().equalsIgnoreCase("RAW"))) {

            // Check if key originates from this factory
            if (key instanceof SDFPBKDF2KeyImpl) {
                return key;
            }
            // Check if key implements the PBEKey
            if (key instanceof javax.crypto.interfaces.PBEKey) {
                javax.crypto.interfaces.PBEKey pKey =
                        (javax.crypto.interfaces.PBEKey) key;
                try {
                    PBEKeySpec spec =
                            new PBEKeySpec(pKey.getPassword(),
                                    pKey.getSalt(),
                                    pKey.getIterationCount(),
                                    pKey.getEncoded().length * 8);
                    return new SDFPBKDF2KeyImpl(spec, digestAlgo);
                } catch (InvalidKeySpecException re) {
                    InvalidKeyException ike = new InvalidKeyException
                            ("Invalid key component(s)");
                    ike.initCause(re);
                    throw ike;
                }
            }
        }
        throw new InvalidKeyException("Invalid key format/algorithm");
    }

    public static final class HmacSM3 extends SDFPBKDF2Core {
        public HmacSM3() {
            super("SM3");
        }
    }

    public static final class HmacSHA1 extends SDFPBKDF2Core {
        public HmacSHA1() {
            super("SHA-1");
        }
    }

    public static final class HmacSHA224 extends SDFPBKDF2Core {
        public HmacSHA224() {
            super("SHA-224");
        }
    }

    public static final class HmacSHA256 extends SDFPBKDF2Core {
        public HmacSHA256() {
            super("SHA-256");
        }
    }

    public static final class HmacSHA384 extends SDFPBKDF2Core {
        public HmacSHA384() {
            super("SHA-384");
        }
    }

    public static final class HmacSHA512 extends SDFPBKDF2Core {
        public HmacSHA512() {
            super("SHA-512");
        }
    }

}
