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

import org.openjdk.jmh.annotations.*;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 10)
@Measurement(iterations = 3, time = 10)
@Fork(value = 1, jvmArgsPrepend = {"-XX:+AlwaysPreTouch"})
@Threads(1)
@State(Scope.Thread)
public class BaseBenchmark {
    private static final String DEFAULT_PROVIDER_NAME = "org.openeuler.BGMJCEProvider";

    protected Provider provider;

    // SDFProvider flag
    protected boolean sdfProviderFlag = false;

    protected void setUp() throws Exception {
        String providerName = System.getProperty("benchmark.provider.name");
        if (providerName == null || providerName.isEmpty()) {
            providerName = DEFAULT_PROVIDER_NAME;
        }
        System.out.println("provider=" + providerName);
        if (providerName.contains("SDFProvider")) {
            sdfProviderFlag = true;
            initKekInfo();
        }
        try {
            Class<?> clazz = Class.forName(providerName);
            provider = (Provider) clazz.newInstance();
            Security.insertProviderAt(provider, 1);
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private void initKekInfo() {
        System.setProperty("sdf.sdkConfig", System.getProperty("sdf.sdkConfig"));
        System.setProperty("sdf.defaultKEKId", System.getProperty("sdf.defaultKEKId"));
        System.setProperty("sdf.defaultRegionId", System.getProperty("sdf.defaultRegionId"));
        System.setProperty("sdf.defaultCdpId", System.getProperty("sdf.defaultCdpId"));
    }

    protected byte[][] fillRandom(byte[][] data) {
        Random rnd = new Random();
        for (byte[] d : data) {
            rnd.nextBytes(d);
        }
        return data;
    }

    protected byte[] fillRandom(byte[] data) {
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(data);
        return data;
    }
}