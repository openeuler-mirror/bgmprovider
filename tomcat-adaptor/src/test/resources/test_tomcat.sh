#!/bin/bash

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

# The supported Tomcat versions are as follows:
# 8.5.x   8.5.2 and above
# 9.0.x   9.0.0.M3 and above
# 10.0.x  all

# Tomcat 8.5.x
tomcat_8_5_x=(
"8.5.73"
"8.5.72"
"8.5.71"
"8.5.70"
"8.5.69"
"8.5.68"
"8.5.66"
"8.5.65"
"8.5.64"
"8.5.63"
"8.5.61"
"8.5.60"
"8.5.59"
"8.5.58"
"8.5.57"
"8.5.56"
"8.5.55"
"8.5.54"
"8.5.53"
"8.5.51"
"8.5.50"
"8.5.49"
"8.5.47"
"8.5.46"
"8.5.45"
"8.5.43"
"8.5.42"
"8.5.41"
"8.5.40"
"8.5.39"
"8.5.38"
"8.5.37"
"8.5.35"
"8.5.34"
"8.5.33"
"8.5.32"
"8.5.31"
"8.5.30"
"8.5.29"
"8.5.28"
"8.5.27"
"8.5.24"
"8.5.23"
"8.5.21"
"8.5.20"
"8.5.19"
"8.5.16"
"8.5.15"
"8.5.14"
"8.5.13"
"8.5.12"
"8.5.11"
"8.5.9"
"8.5.8"
"8.5.6"
"8.5.5"
"8.5.4"
"8.5.3"
"8.5.2"
)

# Tomcat 9.0.x
tomcat_9_0_x=(
"9.0.56"
"9.0.55"
"9.0.54"
"9.0.53"
"9.0.52"
"9.0.50"
"9.0.48"
"9.0.46"
"9.0.45"
"9.0.44"
"9.0.43"
"9.0.41"
"9.0.40"
"9.0.39"
"9.0.38"
"9.0.37"
"9.0.36"
"9.0.35"
"9.0.34"
"9.0.33"
"9.0.31"
"9.0.30"
"9.0.29"
"9.0.27"
"9.0.26"
"9.0.24"
"9.0.22"
"9.0.21"
"9.0.20"
"9.0.19"
"9.0.17"
"9.0.16"
"9.0.14"
"9.0.13"
"9.0.12"
"9.0.11"
"9.0.10"
"9.0.8"
"9.0.7"
"9.0.6"
"9.0.5"
"9.0.4"
"9.0.2"
"9.0.1"
"9.0.0.M27"
"9.0.0.M26"
"9.0.0.M25"
"9.0.0.M22"
"9.0.0.M21"
"9.0.0.M20"
"9.0.0.M19"
"9.0.0.M18"
"9.0.0.M17"
"9.0.0.M15"
"9.0.0.M13"
"9.0.0.M11"
"9.0.0.M10"
"9.0.0.M9"
"9.0.0.M8"
"9.0.0.M6"
"9.0.0.M4"
"9.0.0.M3"
)

# Tomcat 10.0.x
tomcat_10_0_x=(
"10.0.14"
"10.0.13"
"10.0.12"
"10.0.11"
"10.0.10"
"10.0.8"
"10.0.7"
"10.0.6"
"10.0.5"
"10.0.4"
"10.0.2"
"10.0.0"
"10.0.0-M10"
"10.0.0-M9"
"10.0.0-M8"
"10.0.0-M7"
"10.0.0-M6"
"10.0.0-M5"
"10.0.0-M4"
"10.0.0-M3"
"10.0.0-M1"
)
# All tomcat version
tomcat_versions=(${tomcat_8_5_x[@]} ${tomcat_9_0_x[@]} ${tomcat_10_0_x[@]})

if [ ! -d "$PWD/logs" ]; then
    mkdir "$PWD/logs"
fi

i=0
result_log=$PWD/logs/result.log
if [ -f "$result_log" ]; then
    rm $result_log
fi

# java version
if [ -z "$JAVA_HOME" ]; then
  JAVA_CMD="java"
else
  JAVA_CMD="$JAVA_HOME/bin/java"
fi
$JAVA_CMD -version >> $result_log 2>&1
java_version=`$JAVA_CMD -version 2>&1 | sed '1!d' | sed -e 's/"//g' | awk '{print $3}'`
exclude_versions=()
if [[ "$java_version" =~ ^11.* ]]; then
    exclude_versions=(
      "8.5.24"
      "9.0.2"
      "9.0.1"
      "9.0.0.M27"
      "9.0.0.M26"
      "9.0.0.M25"
      "9.0.0.M22"
      "9.0.0.M21"
      "9.0.0.M20"
      "9.0.0.M19"
      "9.0.0.M18"
    )
fi

for ele in ${tomcat_versions[@]}
do
    echo "Start test tomcat $ele"  >> $result_log 2>&1

    if [[ " ${exclude_versions[@]} " =~ " $ele " ]]; then
        echo "Skip tomcat version $ele" >> $result_log 2>&1
        echo "End test tomcat $ele" >> $result_log 2>&1
        echo "===============================" >> $result_log 2>&1
        continue;
    fi
    
    detail_log=$PWD/logs/$ele.log
    if [ -f "$detail_log" ]; then
        rm $detail_log
    fi

    mvn -Dtomcat.version=$ele clean test > $detail_log 2>&1
    
    if [ $? -ne 0 ]; then
        echo "Test tomcat $ele failed!" >> $result_log 2>&1
    else
        echo "Test tomcat $ele success!" >> $result_log 2>&1
    fi
    
    echo "End test tomcat $ele" >> $result_log 2>&1
    echo "===============================" >> $result_log 2>&1
done
