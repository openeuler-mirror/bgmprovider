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

package org.openeuler.provider;

import org.openeuler.adaptor.CompatibleOracleJdkHandler;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Iterator;

public abstract class AbstractProvider extends Provider {

    protected AbstractProvider(String name, double version, String info) {
        super(name, version, info);
        putEntries(this);
        CompatibleOracleJdkHandler.skipJarVerify(this);
    }

    protected void putEntries(AbstractEntries entries) {
        Iterator<Service> iterator = entries.iterator();
        if (System.getSecurityManager() == null) {
            putEntries(iterator);
        } else {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    putEntries(iterator);
                    return null;
                }
            });
        }
    }

    protected void putEntries(Provider provider) {
        AbstractEntries entries = createEntries(provider);
        putEntries(entries);
    }

    protected abstract AbstractEntries createEntries(Provider provider);

    private void putEntries(Iterator<Provider.Service> iterator) {
        while (iterator.hasNext()) {
            putService(iterator.next());
        }
    }
}
