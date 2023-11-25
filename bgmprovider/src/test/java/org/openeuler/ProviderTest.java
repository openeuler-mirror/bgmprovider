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

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.BGMProvider;

import java.security.Provider;
import java.util.Set;
import java.util.TreeSet;

public class ProviderTest {

    @Test
    public void testServices() {
        Set<String> actualServices = new TreeSet<>();
        buildServiceItems(new BGMJCEProvider(), actualServices);
        buildServiceItems(new BGMJSSEProvider(), actualServices);

        Set<String> expectedServices = new TreeSet<>();
        buildServiceItems(new BGMProvider(), expectedServices);

        Assert.assertEquals("Registered services are not equal", expectedServices, actualServices);
    }

    private static void buildServiceItems(Provider provider, Set<String> set) {
        Set<Provider.Service> jceServices = provider.getServices();
        for (Provider.Service service : jceServices) {
            String serviceItem = service.toString().substring(service.getProvider().getName().length() + 1);
            set.add(serviceItem);
        }
    }
}
