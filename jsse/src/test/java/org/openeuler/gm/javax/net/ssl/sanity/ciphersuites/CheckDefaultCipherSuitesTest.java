/*
 * Copyright (c) 2002, 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.gm.javax.net.ssl.sanity.ciphersuites;

/*
 * @test
 * @bug 4750141 4895631 8217579
 * @summary Check enabled and supported ciphersuites are correct
 * @run main/othervm -Djdk.tls.client.protocols="TLSv1.3,TLSv1.2,TLSv1.1,TLSv1,SSLv3" CheckCipherSuites default
 * @run main/othervm -Djdk.tls.client.protocols="TLSv1.3,TLSv1.2,TLSv1.1,TLSv1,SSLv3" CheckCipherSuites limited
 */

import org.junit.Test;

public class CheckDefaultCipherSuitesTest {

    @Test
    public void testCheckDefaultCipherSuites() throws Exception {
        System.setProperty("jdk.tls.client.protocols", "GMTLS, TLSv1.3,TLSv1.2,TLSv1.1,TLSv1,SSLv3");
        CheckCipherSuites.main(new String[]{"default"});
    }
}
