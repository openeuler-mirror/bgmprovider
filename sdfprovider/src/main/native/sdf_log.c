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
#include "org_openeuler_sdf_wrapper_SDFLogNative.h"
#include "sdf_log.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

// log file ptr
static FILE *sdf_log_file;
static SDFLogLevel sdf_log_level;

static void sdf_log_init(const char *log_file_path, int log_level) {
  if (sdf_log_file == NULL && log_level > LEVEL_OFF) {
    sdf_log_file = fopen(log_file_path, "a");
  }
  sdf_log_level = log_level;
}

static void sdf_log_destroy() {
  if (sdf_log_file != NULL) {
    fclose(sdf_log_file);
    sdf_log_file = NULL;
  }
}

int jio_vsnprintf(char *str, size_t count, const char *fmt, va_list args) {
  if ((intptr_t) count <= 0) return -1;

  int result = vsnprintf(str, count, fmt, args);
  if (result > 0 && (size_t) result >= count) {
    result = -1;
  }

  return result;
}

int jio_snprintf(char *str, size_t count, const char *fmt, ...) {
  va_list args;
  int len;
  va_start(args, fmt);
  len = jio_vsnprintf(str, count, fmt, args);
  va_end(args);
  return len;
}

char *local_time_string(char *buf, size_t buflen) {
  struct tm t;
  time_t long_time;
  time(&long_time);
  localtime_r(&long_time, &t);
  jio_snprintf(buf, buflen, "%d-%02d-%02d %02d:%02d:%02d",
               t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
               t.tm_hour, t.tm_min, t.tm_sec);
  return buf;
}

void sdf_write_log(FILE *stream, const char *func, const char *file, const int line,
                   int level, const char *type, char *time_str, char *fmt_str) {
  if (sdf_log_level <= LEVEL_INFO) {
    fprintf(stream, "[%-7s]%s[%s] %s\n", type, time_str, func, fmt_str);
  } else {
    fprintf(stream, "[%-7s]%s[%s@%s:%d] %s\n", type, time_str, func,
            file, line, fmt_str);
  }
}

void sdf_log_message(const char *func, const char *file, const int line,
                     int level, const char *type, const char *format, ...) {
  if (level > sdf_log_level) {
    return;
  }
  char time_str[32];
  local_time_string(time_str, sizeof(time_str));

  va_list ap;
  va_start(ap, format);
  char fmt_str[2048];
  vsnprintf(fmt_str, sizeof(fmt_str), format, ap);
  va_end(ap);

  if (sdf_log_file != NULL) {
    sdf_write_log(sdf_log_file, func, file, line, level, type, time_str, fmt_str);
  } else {
    sdf_write_log(stdout, func, file, line, level, type, time_str, fmt_str);
  }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFLogNative
 * Method:    init
 * Signature: (Ljava/lang/String;I)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFLogNative_init
  (JNIEnv *env, jclass jClazz, jstring jFileName, jint jLevel) {
  const char *logFileName = NULL;
  if (jFileName != NULL) {
    logFileName = (*env)->GetStringUTFChars(env, jFileName, NULL);
  }
  sdf_log_init(logFileName, jLevel);
  if (logFileName != NULL) {
    (*env)->ReleaseStringUTFChars(env, jFileName, logFileName);
  }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFLogNative
 * Method:    destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFLogNative_destroy
  (JNIEnv *env, jclass jClazz) {
  sdf_log_destroy();
}

/*void main() {
  sdf_log_init(NULL, LEVEL_DEBUG);
  SDF_LOG_ERROR("%s", "Test ERROR");
  SDF_LOG_WARING("%s", "Test WARNING");
  SDF_LOG_INFO("%s", "Test INFO");
  SDF_LOG_DEBUG("%s", "Test DEBUG");
  sdf_log_destroy();
}*/
