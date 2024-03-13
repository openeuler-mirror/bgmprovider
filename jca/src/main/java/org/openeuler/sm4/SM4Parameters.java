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

package org.openeuler.sm4;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM4Parameters extends AlgorithmParametersSpi {

    private byte[] iv;
    private GCMParameterSpec gcmParameterSpec;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if(paramSpec==null){
            throw new InvalidParameterSpecException();
        }else{
            if(!(paramSpec instanceof GCMParameterSpec)){
                if (!(paramSpec instanceof IvParameterSpec)) {
                    throw new InvalidParameterSpecException();
                } else {
                    this.iv = ((IvParameterSpec) paramSpec).getIV();
                }
            }else {
                this.gcmParameterSpec = (GCMParameterSpec) paramSpec;
            }
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException();
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
            throw new IOException();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if(paramSpec!=GCMParameterSpec.class){
            if(paramSpec!=IvParameterSpec.class){
                throw new InvalidParameterSpecException();
            }else {
                return (T) new IvParameterSpec(this.iv);
            }
        }else{
         return (T) gcmParameterSpec;
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException();
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw  new IOException();
    }

    @Override
    protected String engineToString() {
        return "SM4 Parameters";
    }
}
