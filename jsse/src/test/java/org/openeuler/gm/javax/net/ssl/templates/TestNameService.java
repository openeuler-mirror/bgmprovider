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

package org.openeuler.gm.javax.net.ssl.templates;

import sun.net.spi.nameservice.NameService;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

/**
 * Set "www.example.com" to loopback address.
 * Just for JDK8
 */
public class TestNameService implements NameService {

    @Override
    public InetAddress[] lookupAllHostAddr(String hostName) throws UnknownHostException {
        if ("www.example.com".equals(hostName) || "www.example.com.".equals(hostName)) {
            return new InetAddress[] { InetAddress.getLoopbackAddress() };
        } else {
            throw new UnknownHostException();
        }
    }

    @Override
    public String getHostByAddr(byte[] param) throws UnknownHostException {
        throw new UnknownHostException();
    }

    static {
        // Set up the test name service
        try {
            Field nameServiceField = InetAddress.class.getDeclaredField("nameServices");
            nameServiceField.setAccessible(true);
            ArrayList<NameService> nameServices = (ArrayList<NameService>) nameServiceField.get(null);
            nameServices.clear();
            nameServices.add(new TestNameService());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
