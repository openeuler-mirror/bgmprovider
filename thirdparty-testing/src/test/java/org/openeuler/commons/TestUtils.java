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

package org.openeuler.commons;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class TestUtils {

    public static String getPath(String fileName) {
        URL url = BaseTest.class.getClassLoader().getResource(fileName);
        if (url != null) {
            try {
                return new URI(url.getPath()).getPath();
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return null;
    }

    public static String[] getPaths(String[] fileNames) {
        String[] expectedPaths = new String[fileNames.length];
        for (int i = 0; i < fileNames.length; i++) {
            expectedPaths[i] = getPath(fileNames[i]);
        }
        return expectedPaths;
    }
}
