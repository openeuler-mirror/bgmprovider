#!/bin/sh

# Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.  Huawei designates this
# particular file as subject to the "Classpath" exception as provided
# by Huawei in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please visit https://gitee.com/openeuler/bgmprovider if you need additional
# information or have any questions.

# Generate server-side keystore
bash generate_key.sh server

# Generate client-side keystore
bash generate_key.sh client

# Generate a keystore with different keypass and storepass
cp server.keystore server-diff-pass.keystore
keytool -keypasswd -keystore server-diff-pass.keystore -alias server-rsa -storepass 12345678  -keypass 12345678 -new rsa12345678
keytool -keypasswd -keystore server-diff-pass.keystore -alias server-ec -storepass 12345678  -keypass 12345678 -new ec12345678
keytool -keypasswd -keystore server-diff-pass.keystore -alias server-sm2-sig -storepass 12345678  -keypass 12345678 -new sm2sig12345678
keytool -keypasswd -keystore server-diff-pass.keystore -alias server-sm2-enc -storepass 12345678  -keypass 12345678 -new sm2enc12345678