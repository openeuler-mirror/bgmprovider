/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.commons.config;

interface SDFConfigConstant {
    String SDF_CONFIG = "sdf.config";
    String SDF_ENABLE_NON_SM = "sdf.enableNonSM";
    String SDF_LIBRARY = "sdf.library";
    String SDF_USEENCDEK = "sdf.useEncDEK";
    String SDF_DEFAULT_KEK_ID = "sdf.defaultKEKId";
    String SDF_DEFAULT_REGION_ID = "sdf.defaultRegionId";
    String SDF_DEFAULT_CDP_ID = "sdf.defaultCdpId";
    String SDF_DEFAULT_PIN = "sdf.defaultPin";
    String SDF_LOG_PATH = "sdf.logPath";
    // valid log level : OFF,ERROR,WARNING,INFO,DEBUG
    String SDF_LOG_LEVEL = "sdf.logLevel";
    String SDF_CLEANER_SHORT_INTERVAL = "sdf.cleaner.shortInterval";
    String SDF_CLEANER_LONG_INTERVAL = "sdf.cleaner.longInterval";
    String SDF_SDK_CONFIG = "sdf.sdkConfig";
}
