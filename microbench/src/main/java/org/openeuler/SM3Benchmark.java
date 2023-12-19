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

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import java.security.MessageDigest;

public class SM3Benchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;

    @Param({"SM3"})
    private String algorithm;

    @Param({"" + 1024,
            "" + 10 * 1024,
            "" + 100 * 1024,
            "" + 1024 * 1024})
    private int dataSize;

    private byte[][] data;
    private int index = 0;
    private MessageDigest md;

    @Setup
    public void setUp() throws Exception {
        super.setUp();
        data = fillRandom(new byte[SET_SIZE][dataSize]);
        md = (provider == null) ?
                MessageDigest.getInstance(algorithm) :
                MessageDigest.getInstance(algorithm, provider);
    }

    @Benchmark
    public byte[] digest() {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        return md.digest(d);
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public byte[] digestLegacy() {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        return md.digest(d);
    }
}