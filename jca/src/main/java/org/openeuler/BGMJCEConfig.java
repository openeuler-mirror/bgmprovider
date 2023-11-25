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

class BGMJCEConfig {
    static boolean enableSM2() {
        return Config.enable("jce.sm2");
    }

    static boolean enableEC() {
        return Config.enable("jce.ec");
    }

    static boolean enableSM3() {
        return Config.enable("jce.sm3");
    }

    static boolean enableSM4() {
        return Config.enable("jce.sm3");
    }

    static boolean enableSM3withSM2() {
        return Config.enable("jce.signatureSM3withSM2");
    }

    static boolean enablePBES2() {
        return Config.enable("jce.pbes2");
    }
}
