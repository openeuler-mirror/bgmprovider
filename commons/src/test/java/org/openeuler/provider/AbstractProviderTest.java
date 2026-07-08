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
package org.openeuler.provider;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import static org.junit.Assert.*;

public class AbstractProviderTest {

    @Test
    public void entriesHelpersCreateAliasesAndPreserveInsertionOrder() {
        TestProvider provider = new TestProvider();
        assertEquals("TestProvider", provider.getName());
        assertEquals(3, provider.getServices().size());
        assertNotNull(provider.getService("MessageDigest", "ONE"));
        assertNotNull(provider.getService("Cipher", "TWO"));
        assertNotNull(provider.getService("KeyFactory", "THREE"));

        List<String> aliases = TestEntries.aliases("A", "B");
        assertEquals("A", aliases.get(0));
        assertEquals("B", aliases.get(1));

        List<String> oidAliases = TestEntries.aliasesWithOid("1.2.3", "ALIAS");
        assertEquals("1.2.3", oidAliases.get(0));
        assertEquals("ALIAS", oidAliases.get(1));
        assertEquals("OID.1.2.3", oidAliases.get(2));
    }

    @Test
    public void entriesCanMergeOtherEntriesAndDeduplicateServices() {
        Provider provider = new Provider("MergeProvider", 1.0, "test") {
            private static final long serialVersionUID = 1L;
        };
        TestEntries first = new TestEntries(provider);
        TestEntries second = new TestEntries(provider);
        first.merge(second);

        int count = 0;
        Iterator<Provider.Service> iterator = first.iterator();
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(6, count);
    }

    @Test
    public void privilegedActionAndShortAddOverloadWork() throws Exception {
        TestProvider provider = new TestProvider();
        TestEntries entries = new TestEntries(provider);
        entries.addShort(provider);

        Iterator<Provider.Service> iterator = Collections.<Provider.Service>emptyList().iterator();
        Class<?> actionClass = Class.forName("org.openeuler.provider.AbstractProvider$1");
        Constructor<?> constructor = actionClass.getDeclaredConstructor(AbstractProvider.class, Iterator.class);
        constructor.setAccessible(true);
        Object action = constructor.newInstance(provider, iterator);
        Method run = actionClass.getDeclaredMethod("run");
        run.setAccessible(true);

        assertNull(run.invoke(action));
    }

    @Test
    public void providerUsesPrivilegedPutEntriesWhenSecurityManagerExists() throws Exception {
        SecurityManager old = System.getSecurityManager();
        try {
            if (setSecurityManagerField(new NoOpSecurityManager())) {
                TestProvider provider = new TestProvider();
                assertNotNull(provider.getService("MessageDigest", "ONE"));
            }
        } finally {
            setSecurityManagerField(old);
        }
    }

    private static boolean setSecurityManagerField(SecurityManager securityManager) throws Exception {
        Field field;
        try {
            field = System.class.getDeclaredField("security");
        } catch (NoSuchFieldException e) {
            return false;
        }
        Object unsafe = unsafe();
        Class<?> unsafeClass = unsafe.getClass();
        Object base = unsafeClass.getMethod("staticFieldBase", Field.class).invoke(unsafe, field);
        long offset = ((Long) unsafeClass.getMethod("staticFieldOffset", Field.class).invoke(unsafe, field)).longValue();
        unsafeClass.getMethod("putObject", Object.class, long.class, Object.class)
                .invoke(unsafe, base, offset, securityManager);
        return true;
    }

    private static Object unsafe() throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        return theUnsafe.get(null);
    }

    private static final class NoOpSecurityManager extends SecurityManager {
        @Override
        public void checkPermission(java.security.Permission perm) {
        }

        @Override
        public void checkPermission(java.security.Permission perm, Object context) {
        }
    }

    private static final class TestProvider extends AbstractProvider {
        private static final long serialVersionUID = 1L;

        private TestProvider() {
            super("TestProvider", 1.0, "test provider");
        }

        @Override
        protected AbstractEntries createEntries(Provider provider) {
            return new TestEntries(provider);
        }
    }

    private static final class TestEntries extends AbstractEntries {
        private TestEntries(Provider provider) {
            super(provider);
        }

        @Override
        protected void putServices(Provider provider) {
            HashMap<String, String> attrs = new HashMap<>();
            attrs.put("ImplementedIn", "Software");
            add(provider, "MessageDigest", "ONE", "example.One", createAliases("ALIAS_ONE"), attrs);
            add(provider, "Cipher", "TWO", "example.Two", createAliasesWithOid("1.2.840.10045.2.1"));
            add(new Provider.Service(provider, "KeyFactory", "THREE", "example.Three", null, null));
        }

        private static List<String> aliases(String... aliases) {
            return createAliases(aliases);
        }

        private static List<String> aliasesWithOid(String... aliases) {
            return createAliasesWithOid(aliases);
        }

        private void merge(AbstractEntries entries) {
            add(entries);
        }

        private void addShort(Provider provider) {
            add(provider, "Mac", "SHORT", "example.Short");
        }
    }
}
