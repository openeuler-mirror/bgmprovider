/*
 * Copyright (c) 2025, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jsse.ssl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import java.security.*;

abstract class SDFKeyManagerFactory extends KeyManagerFactorySpi {
    X509ExtendedKeyManager keyManager;
    boolean isInitialized;
    byte[] pin;

    SDFKeyManagerFactory() {
        // empty
    }

    /**
     * Returns one key manager for each type of key material.
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (!isInitialized) {
            throw new IllegalStateException(
                    "KeyManagerFactoryImpl is not initialized");
        }
        return new KeyManager[] { keyManager };
    }

    // Factory for the SunX509 keymanager
    public static final class SunX509 extends SDFKeyManagerFactory {

        @Override
        protected void engineInit(KeyStore ks, char[] password) throws
                KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
            try {
                keyManager = new SDFSunX509KeyManager(ks, password, pin);
            } catch (InvalidKeyException e) {
                throw new KeyStoreException("SDFSunX509KeyManager engineInit failed.");
            }

            isInitialized = true;
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec) throws
                InvalidAlgorithmParameterException {
            if (!(spec instanceof SDFManagerFactoryParameters)) {
                throw new InvalidAlgorithmParameterException(
                        "SDFSunX509KeyManager does not use SDFManagerFactoryParameters");
            }
            SDFManagerFactoryParameters params = (SDFManagerFactoryParameters) spec;
            pin = params.getPin();
        }
    }
}
