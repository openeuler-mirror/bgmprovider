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

import java.security.Provider;
import java.util.*;

public abstract class AbstractEntries {
    private final LinkedHashSet<Provider.Service> services;

    AbstractEntries(Provider provider) {
        this.services = new LinkedHashSet<>();
        putServices(provider);
    }

    // create an aliases List from the specified aliases
    protected static List<String> createAliases(String... aliases) {
        return Arrays.asList(aliases);
    }

    // create an aliases List from the specified oid followed by other aliases
    protected static List<String> createAliasesWithOid(String... oids) {
        String[] result = Arrays.copyOf(oids, oids.length + 1);
        result[result.length - 1] = "OID." + oids[0];
        return Arrays.asList(result);
    }

    Iterator<Provider.Service> iterator() {
        return services.iterator();
    }

    protected void add(Provider provider, String type, String algo, String className, List<String> aliases,
                     HashMap<String, String> attrs) {
        services.add(new Provider.Service(provider, type, algo, className, aliases, attrs));
    }

    protected void add(Provider provider, String type, String algo, String className, List<String> aliases) {
        add(provider, type, algo, className, aliases, null);
    }

    protected void add(Provider provider, String type, String algo, String className) {
        add(provider, type, algo, className, null);
    }

    protected void add(Provider.Service service) {
        services.add(service);
    }

    protected void add(AbstractEntries entries) {
        Iterator<Provider.Service> iterator = entries.iterator();
        while (iterator.hasNext()) {
            Provider.Service service = iterator.next();
            add(service);
        }
    }

    protected abstract void putServices(Provider provider);
}
