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

public class SM2P256V1PointTest {

    @Test
    public void test() {
        int[] x1 = new int[]{
                -2077287887, -1574109636, -1183922085, 624014447, -1178401550, 656069030, 1652997732, -2024076056
        };

        int[] y1 = new int[]{
                1612725891, 1334858461, 370554127, -318865266, -875182322, 933824583, -597090818, -1608527127
        };

        int[] z1 = new int[]{
                0, -749717373, 849606050, 1151397406, 1724711450, 985617297, 679141493, -1860660963
        };
        SM2P256V1Point p1 = new SM2P256V1Point(x1, y1, z1);
        Assert.assertFalse(p1.isInfinity());
        Assert.assertTrue(SM2P256V1Point.getPointInfinity().isInfinity());
    }
}
