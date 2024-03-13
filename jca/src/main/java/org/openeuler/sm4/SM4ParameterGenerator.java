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
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM4ParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private SecureRandom random;
    private AlgorithmParameterSpec param;
    private AlgorithmParameters parameters;
    @Override
    protected void engineInit(int size, SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
        if(genParamSpec.getClass().equals(IvParameterSpec.class)){
            param = genParamSpec;
        }else if(genParamSpec.getClass().equals(GCMParameterSpec.class)){
            param =genParamSpec;
        }else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        try {
            parameters = AlgorithmParameters.getInstance("SM4");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
       if(param==null){
            byte[] iv = new byte[16];
            if(this.random==null){
                random = new SecureRandom();
            }
            random.nextBytes(iv);
            param = new IvParameterSpec(iv);
            try {
                parameters.init(param);
            } catch (InvalidParameterSpecException e) {
                e.printStackTrace();
            }
        }
        try {
            parameters.init(param);
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return parameters;
    }
}
