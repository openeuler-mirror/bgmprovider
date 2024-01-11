/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

public class BGMJSSEProvider extends AbstractProvider {
    private static final String NAME = "BGMJSSEProvider";
    private static final double VERSION = 1.8d;
    private static final String INFO = "BiSheng GuoMi JSSE Provider " +
            "(support GMTLS/SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3)";

    public BGMJSSEProvider() {
        super(NAME, VERSION, INFO);
    }

    @Override
    protected AbstractEntries createEntries(Provider provider) {
        return createJSSEEntries(provider);
    }

    static AbstractEntries createJSSEEntries(Provider provider) {
        return new BGMJSSEEntries(provider);
    }
}
