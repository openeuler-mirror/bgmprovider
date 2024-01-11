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

package org.openeuler;

import org.openeuler.sun.security.ec.ECKeyFactory;
import org.openeuler.util.GMUtil;
import sun.security.jca.GetInstance;
import sun.security.util.Debug;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

public class ECDHKeyAgreementAdaptor extends KeyAgreementSpi {
    private static final Debug debug = Debug.getInstance("jca", "KeyAgreement");
    private KeyAgreement keyAgreement;

    @Override
    protected void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {
        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("Key must be instance of PrivateKey");
        }
        ECPrivateKey privateKey = (ECPrivateKey) ECKeyFactory.toECKey(key);
        keyAgreement = getKeyAgreement(privateKey.getParams());
        keyAgreement.init(key, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException
                    ("Parameters not supported");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        return keyAgreement.doPhase(key, lastPhase);
    }

    @Override
    protected byte[] engineGenerateSecret()
            throws IllegalStateException {
        return keyAgreement.generateSecret();
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        return keyAgreement.generateSecret(sharedSecret, offset);
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        return keyAgreement.generateSecret(algorithm);
    }

    private static KeyAgreement getKeyAgreement(AlgorithmParameterSpec params) throws InvalidKeyException {
        KeyAgreement keyAgreement;
        try {
            if (GMUtil.isSM2Curve(params)) {
                keyAgreement = KeyAgreement.getInstance("SM2DH");
            } else {
                keyAgreement = getECDHKeyAgreement();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        }
        return keyAgreement;
    }

    private static KeyAgreement getECDHKeyAgreement()
            throws NoSuchAlgorithmException {
        String algorithm = "ECDH";
        KeyAgreement instance = null;
        List<Provider.Service> services =
                GetInstance.getServices("KeyAgreement", algorithm);
        for (Provider.Service s : services) {
            String providerName = s.getProvider().getName();
            if (providerName.equals("BGMJCEProvider")
                    || providerName.equals("BGMProvider")) {
                continue;
            }
            try {
                instance = KeyAgreement.getInstance(algorithm, s.getProvider());
            } catch (NoSuchAlgorithmException e) {
                if (debug != null) {
                    debug.println(e.getMessage());
                }
            }
            if (instance != null) {
                return instance;
            }
        }
        throw new NoSuchAlgorithmException
                ("Algorithm " + algorithm + " not available");
    }
}
