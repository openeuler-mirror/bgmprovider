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

package org.openeuler.sun.security.ssl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;

public class KrbClientKeyExchangeHelper {

    private static final String KRB5_CLASS_NAME =
            "sun.security.ssl.krb5.KrbClientKeyExchangeHelperImpl";

    private static final Class<?> krb5Class = AccessController.doPrivileged(
            new PrivilegedAction<Class<?>>() {
                @Override
                public Class<?> run() {
                    try {
                        return Class.forName(KRB5_CLASS_NAME, true, null);
                    } catch (ClassNotFoundException cnf) {
                        return null;
                    }
                }
            });

    private static Method initRreMaster;
    private static Method initEncodedTicket;
    private static Method getEncodedTicket;
    private static Method getEncryptedPreMasterSecret;
    private static Method getPlainPreMasterSecret;
    private static Method getPeerPrincipal;
    private static Method getLocalPrincipal;
    private static Exception exception;

    private Object krb5Instance;

    static {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    initMethod();
                } catch (NoSuchMethodException e) {
                    exception = e;
                }
                return null;
            }
        });
    }

    private static void initMethod() throws NoSuchMethodException {
        if (krb5Class == null) {
            return;
        }
        initRreMaster = krb5Class.getDeclaredMethod("init",
                byte[].class, String.class, AccessControlContext.class);
        initEncodedTicket = krb5Class.getDeclaredMethod("init",
                byte[].class, byte[].class, Object.class, AccessControlContext.class);
        getEncodedTicket = krb5Class.getDeclaredMethod("getEncodedTicket");
        getEncryptedPreMasterSecret = krb5Class.getDeclaredMethod("getEncryptedPreMasterSecret");
        getPlainPreMasterSecret = krb5Class.getDeclaredMethod("getPlainPreMasterSecret");
        getPeerPrincipal = krb5Class.getDeclaredMethod("getPeerPrincipal");
        getLocalPrincipal = krb5Class.getDeclaredMethod("getLocalPrincipal");
    }

    private static Object newKrb5Instance() {
        if (krb5Class != null) {
            try {
                return krb5Class.getDeclaredConstructor().newInstance();
            } catch (InstantiationException | IllegalAccessException |
                    NoSuchMethodException | InvocationTargetException e) {
                throw new AssertionError(e);
            }
        }
        return null;
    }

    private static void ensureAvailable() {
        if (krb5Class == null) {
            throw new AssertionError("Kerberos is unavailable");
        }
        if (exception != null) {
            throw new AssertionError(exception);
        }
    }

    private static Object invoke(Method method, Object obj, Object... args) {
        try {
            return method.invoke(obj, args);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new AssertionError(e);
        }
    }

    KrbClientKeyExchangeHelper() {
        ensureAvailable();
        krb5Instance = newKrb5Instance();
    }

    void init(byte[] preMaster, String serverName,
              AccessControlContext acc) throws IOException {
        ensureAvailable();
        invoke(initRreMaster, krb5Instance, preMaster, serverName, acc);
    }

    void init(byte[] encodedTicket, byte[] preMasterEnc,
              Object serviceCreds, AccessControlContext acc)
            throws IOException {
        ensureAvailable();
        invoke(initEncodedTicket, krb5Instance, encodedTicket, preMasterEnc, serviceCreds, acc);
    }

    byte[] getEncodedTicket() {
        ensureAvailable();
        return (byte[]) invoke(getEncodedTicket, krb5Instance);
    }

    byte[] getEncryptedPreMasterSecret() {
        ensureAvailable();
        return (byte[]) invoke(getEncryptedPreMasterSecret, krb5Instance);
    }

    byte[] getPlainPreMasterSecret() {
        ensureAvailable();
        return (byte[]) invoke(getPlainPreMasterSecret, krb5Instance);
    }

    Principal getPeerPrincipal() {
        ensureAvailable();
        return (Principal) invoke(getPeerPrincipal, krb5Instance);
    }

    Principal getLocalPrincipal() {
        ensureAvailable();
        return (Principal) invoke(getLocalPrincipal, krb5Instance);
    }
}
