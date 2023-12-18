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

package org.openeuler.org.apache.httpcomponents.client5;
import org.apache.hc.core5.function.Callback;

import javax.net.ssl.SSLParameters;

public class TestSSLServerSetupHandler implements Callback<SSLParameters> {
    private boolean clientAuth;

    public TestSSLServerSetupHandler() {

    }

    public TestSSLServerSetupHandler(boolean clientAuth) {
        this.clientAuth = clientAuth;
    }

    @Override
    public void execute(SSLParameters sslParameters) {
        sslParameters.setProtocols(new String[]{"GMTLS", "TLSv1.2", "TLSv1.3"});
        if (clientAuth) {
            sslParameters.setNeedClientAuth(clientAuth);
        }
    }
}
