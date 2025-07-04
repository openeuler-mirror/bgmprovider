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

#include "sdf_exception.h"

void throwByName(JNIEnv *env, const char *name, const char *message) {
  jclass cls = (*env)->FindClass(env, name);
  if (cls != 0) {
    (*env)->ThrowNew(env, cls, message);
  }
}

void throwOutOfMemoryError(JNIEnv *env, const char *message) {
  throwByName(env, CLASS_OUTOFMEMORYERROR, message);
}

void throwNullPointerException(JNIEnv *env, const char *message) {
  throwByName(env, CLASS_NULLPOINTEREXCEPTION, message);
}

void throwSDFRuntimeException(JNIEnv *env, const char *message) {
  throwByName(env, CLASS_SDFRUNTIMEEXCEPTION, message);
}

void throwIllegalArgumentException(JNIEnv *env, const char *message) {
    throwByName(env, CLASS_ILLEGALARGUMENTEXCEPTION, message);
}

void throwSDFException(JNIEnv *env, int errorCode, const char* funcName) {
  jclass jSDFExceptionClass = NULL;
  jSDFExceptionClass = (*env)->FindClass(env, CLASS_SDFEXCEPTION);
  if (jSDFExceptionClass == NULL) {
      goto cleanup;
  }

  jmethodID jConstructor = NULL;
  jConstructor = (*env)->GetMethodID(env, jSDFExceptionClass, "<init>", "(JLjava/lang/String;)V");
  if (jConstructor == NULL) {
      goto cleanup;
  }

  jthrowable jPKCS11Exception = NULL;
  jlong jErrorCode = (jlong) errorCode;
  jstring jFuncName = (*env)->NewStringUTF(env, funcName);
  jPKCS11Exception = (jthrowable) (*env)->NewObject(env, jSDFExceptionClass, jConstructor, jErrorCode, jFuncName);
  if (jPKCS11Exception == NULL) {
      goto cleanup;
  }
  (*env)->Throw(env, jPKCS11Exception);
cleanup:
    if (jSDFExceptionClass) {
        (*env)->DeleteLocalRef(env, jSDFExceptionClass);
    }
}