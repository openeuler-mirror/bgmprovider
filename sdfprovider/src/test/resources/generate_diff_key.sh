#!/bin/sh

# Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

kekid=$1
if [ ! $kekid ]; then
    kekid="KekId123456789012345678901234567"
fi
regionid=$2
if [ ! $regionid ]; then
    regionid="RegionID1"
fi

cdpid=$3
if [ ! $cdpid ]; then
    cdpid="CdpID1"
fi
# Generate a keystore with encrypt key
keytool -J-Dsdf.useEncDEK=true -J-Dsdf.defaultKEKId=$kekid -J-Dsdf.defaultRegionId=$regionid -J-Dsdf.defaultCpdId=$cdpid  -genkey -keyalg SM2 -sigalg SM3withSM2 -keysize 256 -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1  -keystore server-enc-key.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias server-enc-key -dname "CN=server/sm2/enc" -validity 3650 -storetype pkcs12

# Generate a keystore with normal key
#keytool -genkey -keyalg SM2 -sigalg SM3withSM2 -keysize 256 -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1  -keystore server-normal-key.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias server-normal-key -dname "CN=server/sm2/normal" -validity 3650 -storetype pkcs12

