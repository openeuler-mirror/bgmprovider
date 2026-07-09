/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
package org.openeuler.adaptor;

import org.junit.Test;

import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CompatibleOracleJdkHandlerTest {

    @Test
    public void constructorAndWrapperFactoriesWork() throws Exception {
        assertNotNull(new CompatibleOracleJdkHandler());

        Provider provider = new Provider("WrapperProvider", 1.0, "test") {
            private static final long serialVersionUID = 1L;
        };
        Field identity = field("identityWrapperConstructor");
        Field weakIdentity = field("weakIdentityWrapperConstructor");
        Field queue = field("queue");

        Object oldIdentity = identity.get(null);
        Object oldWeakIdentity = weakIdentity.get(null);
        Object oldQueue = queue.get(null);
        try {
            identity.set(null, IdentityWrapperStub.class.getDeclaredConstructor(Provider.class));
            Method newIdentityWrapper = CompatibleOracleJdkHandler.class
                    .getDeclaredMethod("newIdentityWrapper", Provider.class);
            newIdentityWrapper.setAccessible(true);
            assertTrue(newIdentityWrapper.invoke(null, provider) instanceof IdentityWrapperStub);

            weakIdentity.set(null,
                    WeakIdentityWrapperStub.class.getDeclaredConstructor(Provider.class, ReferenceQueue.class));
            queue.set(null, new ReferenceQueue<Object>());
            Method newWeakIdentityWrapper = CompatibleOracleJdkHandler.class
                    .getDeclaredMethod("newWeakIdentityWrapper", Provider.class);
            newWeakIdentityWrapper.setAccessible(true);
            assertTrue(newWeakIdentityWrapper.invoke(null, provider) instanceof WeakIdentityWrapperStub);
        } finally {
            identity.set(null, oldIdentity);
            weakIdentity.set(null, oldWeakIdentity);
            queue.set(null, oldQueue);
        }
    }

    @Test
    public void oracleVendorInitializationRunsInIsolatedClassLoader() throws Exception {
        String oldVendor = System.getProperty("java.vendor");
        try {
            System.setProperty("java.vendor", "Oracle Corporation");
            URLClassLoader loader = new URLClassLoader(new URL[]{Paths.get("target", "classes").toUri().toURL()}, null);
            try {
                Class<?> handler = Class.forName("org.openeuler.adaptor.CompatibleOracleJdkHandler", true, loader);
                Provider provider = new Provider("IsolatedOracleProvider", 1.0, "test") {
                    private static final long serialVersionUID = 1L;
                };
                handler.getDeclaredMethod("skipJarVerify", Provider.class).invoke(null, provider);
            } finally {
                loader.close();
            }
        } finally {
            if (oldVendor == null) {
                System.clearProperty("java.vendor");
            } else {
                System.setProperty("java.vendor", oldVendor);
            }
        }
    }

    @Test
    public void skipJarVerifyCoversUnavailableAndIdentityWrapperBranches() throws Exception {
        Provider provider = new Provider("IdentityBranchProvider", 1.0, "test") {
            private static final long serialVersionUID = 1L;
        };
        Field jceSecurityClass = field("jceSecurityClass");
        Field verificationResults = field("verificationResults");
        Field identity = field("identityWrapperConstructor");
        Field weakIdentity = field("weakIdentityWrapperConstructor");

        Object oldJceSecurityClass = jceSecurityClass.get(null);
        Object oldVerificationResults = verificationResults.get(null);
        Object oldIdentity = identity.get(null);
        Object oldWeakIdentity = weakIdentity.get(null);
        try {
            jceSecurityClass.set(null, CompatibleOracleJdkHandler.class);
            verificationResults.set(null, null);
            CompatibleOracleJdkHandler.skipJarVerify(provider);

            Map<Object, Object> identityResults = new HashMap<>();
            verificationResults.set(null, identityResults);
            identity.set(null, IdentityWrapperStub.class.getDeclaredConstructor(Provider.class));
            weakIdentity.set(null, null);
            CompatibleOracleJdkHandler.skipJarVerify(provider);
            assertTrue(identityResults.size() == 1);
        } finally {
            jceSecurityClass.set(null, oldJceSecurityClass);
            verificationResults.set(null, oldVerificationResults);
            identity.set(null, oldIdentity);
            weakIdentity.set(null, oldWeakIdentity);
        }
    }

    private static Field field(String name) throws Exception {
        Field field = CompatibleOracleJdkHandler.class.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    public static final class IdentityWrapperStub {
        private final Provider provider;

        public IdentityWrapperStub(Provider provider) {
            this.provider = provider;
        }
    }

    public static final class WeakIdentityWrapperStub {
        private final Provider provider;
        private final ReferenceQueue queue;

        public WeakIdentityWrapperStub(Provider provider, ReferenceQueue queue) {
            this.provider = provider;
            this.queue = queue;
        }
    }
}
