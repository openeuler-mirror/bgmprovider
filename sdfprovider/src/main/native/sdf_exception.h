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

#ifndef SDF_EXCEPTION_H
#define SDF_EXCEPTION_H

#include <jni.h>
#include "sdf.h"

#define CLASS_OUTOFMEMORYERROR "java/lang/OutOfMemoryError"
#define CLASS_NULLPOINTEREXCEPTION "java/lang/NullPointerException"
#define CLASS_SDFEXCEPTION "org/openeuler/sdf/commons/exception/SDFException"
#define CLASS_SDFRUNTIMEEXCEPTION "org/openeuler/sdf/commons/exception/SDFRuntimeException"
#define CLASS_ILLEGALARGUMENTEXCEPTION "java/lang/IllegalArgumentException"

// Throws a Java Exception by name
void throwByName(JNIEnv *env, const char *name, const char *message);

// Throws java.lang.OutOfMemoryError
void throwOutOfMemoryError(JNIEnv *env, const char *message);

// Throws java.lang.NullPointerException
void throwNullPointerException(JNIEnv *env, const char *message);

// Throws org.openeuler.sdf.commons.exception.SDFRuntimeException
void throwSDFRuntimeException(JNIEnv *env, const char *message);

// Throws java.lang.IllegalArgumentException
void throwIllegalArgumentException(JNIEnv *env, const char *message);

// Throws org.openeuler.sdf.commons.exception.SDFException
void throwSDFException(JNIEnv *env, SGD_RV errorCode);



#endif // SDF_EXCEPTION_H

