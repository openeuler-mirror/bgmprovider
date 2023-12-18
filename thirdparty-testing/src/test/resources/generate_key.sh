#!/bin/sh

# Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

name=$1
if [ ! $name ]; then
    name="test"
fi

# Remove keystore and truststore
function removeFile()
{
  if [ -f $1 ];then
    rm $1
  fi
}

# removeFile $name-ec.keystore
# removeFile $name-ec.truststore
removeFile $name.keystore
# removeFile $name-rootca.keystore
# removeFile $name-rsa.keystore
# removeFile $name-rsa.truststore
# removeFile $name-sm2-enc.keystore
# removeFile $name-sm2-enc.truststore
# removeFile $name-sm2-sig.keystore
# removeFile $name-sm2-sig.truststore
removeFile $name.truststore

############# CA #############
# Generate CA key
keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=DigitalSignature,nonRepudiation,keyCertSign,crlSign -ext BasicConstraints=CA:true -keystore $name-rootca.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias $name-rootca -dname "CN=$name-rootca" -validity 3650 -storetype pkcs12

# Export CA certificate
keytool -exportcert -keystore $name-rootca.keystore -alias $name-rootca -file $name-rootca.crt -storepass 12345678 -trustcacerts -storetype pkcs12

# Import the CA certificate into $JAVA_HOME/jre/lib/security/cacerts
keytool -import -alias $name-rootca -file $name-rootca.crt -keystore  $JAVA_HOME/jre/lib/security/cacerts -storepass changeit -trustcacerts -noprompt
keytool -importcert -file $name-rootca.crt -alias $name-rootca -keystore $name.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12

############# SM2 Enc #############
# Generate SM2 encryption key
keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1  -keystore $name.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias $name-sm2-enc -dname "CN=$name/sm2/enc" -validity 3650 -storetype pkcs12

# SM2 encryption certificate request
keytool -certreq -alias $name-sm2-enc -sigAlg SM3withSM2 -keystore $name.keystore -file $name-sm2-enc.csr -storepass 12345678 -storetype pkcs12

# Issue SM2 encryption certificate
keytool -gencert -ext KeyUsage=keyEncipherment,dataEncipherment,keyAgreement  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1  -sigalg SM3withSM2  -alias $name-rootca -keystore $name-rootca.keystore -infile $name-sm2-enc.csr -outfile $name-sm2-enc.crt -storepass 12345678 -validity 3650 -storetype pkcs12

# Import SM2 encryption certificate to keystore to generate certificate chain
keytool -import -alias $name-sm2-enc -file $name-sm2-enc.crt -keystore $name.keystore -trustcacerts -storepass 12345678 -trustcacerts -storetype pkcs12

# Import SM2 encryption certificate to truststore
keytool -importcert -file $name-sm2-enc.crt -alias $name-sm2-enc  -keystore $name.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

# Import SM2 encryption key to $name-sm2-enc.keystore
# keytool -importkeystore -srckeystore $name.keystore -srcalias $name-sm2-enc -destalias $name-sm2-enc -destkeystore $name-sm2-enc.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12

# Import SM2 encryption certificate to $name-sm2-enc.truststore
# keytool -importcert -file $name-sm2-enc.crt -alias $name-sm2-enc  -keystore $name-sm2-enc.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

# Import rootca certificate to $name-sm2-enc.truststore
# keytool -importcert -file $name-rootca.crt -alias $name-rootca -keystore $name-sm2-enc.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12

############# SM2 Sig #############

# Generate SM2 signature key
keytool -genkey -keyalg SM2 -sigalg SM3withSM2  -keysize 256 -ext KeyUsage=digitalSignature  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1  -keystore $name.keystore -storepass 12345678 -keypass 12345678 -storetype pkcs12 -alias $name-sm2-sig -dname "CN=$name/sm2/sig" -validity 3650  -storetype pkcs12

# SM2 signature certificate request
keytool -certreq -alias $name-sm2-sig -sigAlg SM3withSM2 -keystore $name.keystore -file $name-sm2-sig.csr -storepass 12345678  -storetype pkcs12

# Issue SM2 signature certificate
keytool -gencert -ext KeyUsage=digitalSignature  -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1   -sigalg SM3withSM2 -alias $name-rootca -keystore $name-rootca.keystore -infile $name-sm2-sig.csr -outfile $name-sm2-sig.crt -storepass 12345678 -validity 3650  -storetype pkcs12

# Import SM2 signature certificate to keystore to generate certificate chain
keytool -import -alias $name-sm2-sig -file $name-sm2-sig.crt -keystore $name.keystore -trustcacerts -storepass 12345678 -trustcacerts -storetype pkcs12

# Import SM2 signature certificate to truststore
keytool -importcert -file $name-sm2-sig.crt -alias $name-sm2-sig  -keystore $name.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

# Import SM2 signature key to $name-sm2-sig.keystore
# keytool -importkeystore -srckeystore $name.keystore -srcalias $name-sm2-sig -destalias $name-sm2-sig -destkeystore $name-sm2-sig.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12

# Import SM2 signature certificate to $name-sm2-sig.truststore
# keytool -importcert -file $name-sm2-sig.crt -alias $name-sm2-sig  -keystore $name-sm2-sig.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

# Import rootca certificate to $name-sm2-sig.truststore
# keytool -importcert -file $name-rootca.crt -alias $name-rootca -keystore $name-sm2-sig.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12

# Delete $name-rootca from $JAVA_HOME/jre/lib/security/cacerts
keytool -delete -alias $name-rootca -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit

########### RSA ###########
keytool -genkeypair -keyalg RSA -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1 -keysize 2048 -alias $name-rsa -keystore $name.keystore -storepass 12345678 -keypass 12345678 -dname "CN=$name/rsa"  -validity 3650  -storetype pkcs12
keytool -exportcert -file $name-rsa.crt -alias $name-rsa -keystore $name.keystore -storepass 12345678  -storetype pkcs12
keytool -importcert -file $name-rsa.crt -alias $name-rsa -keystore $name.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12

# Import RSA key to $name-rsa.keystore
# keytool -importkeystore -srckeystore $name.keystore -srcalias $name-rsa -destalias $name-rsa -destkeystore $name-rsa.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12

# Import RSA certificate to $name-rsa.truststore
# keytool -importcert -file $name-rsa.crt -alias $name-rsa  -keystore $name-rsa.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

########### EC ###########
keytool -genkeypair -keyalg EC -ext SubjectAlternativeName=dns:localhost,ip:127.0.0.1 -alias $name-ec -keystore $name.keystore -storepass 12345678 -keypass 12345678 -dname "CN=$name/ec"  -validity 3650
keytool -exportcert -file $name-ec.crt -alias $name-ec -keystore $name.keystore -storepass 12345678 -storetype pkcs12
keytool -importcert -file $name-ec.crt -alias $name-ec -keystore $name.truststore -storepass 12345678 -trustcacerts -noprompt -storetype pkcs12

# Import EC key to $name-ec.keystore
# keytool -importkeystore -srckeystore $name.keystore -srcalias $name-ec -destalias $name-ec -destkeystore $name-ec.keystore -srckeypass 12345678 -destkeypass 12345678 -srcstorepass 12345678 -deststorepass 12345678 -deststoretype pkcs12

# Import EC certificate to $name-ec.truststore
# keytool -importcert -file $name-ec.crt -alias $name-ec  -keystore $name-ec.truststore -storepass 12345678 -trustcacerts  -noprompt -storetype pkcs12

# Remove crt and csr file
removeFile $name-ec.crt
removeFile $name-rootca.crt
removeFile $name-rsa.crt
removeFile $name-sm2-enc.crt
removeFile $name-sm2-sig.crt

removeFile $name-sm2-enc.csr
removeFile $name-sm2-sig.csr

# Rmove rootca.keystore
removeFile $name-rootca.keystore

