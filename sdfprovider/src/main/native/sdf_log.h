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

#ifndef SDF_LOG_H
#define SDF_LOG_H

typedef enum {
    LEVEL_OFF,
    LEVEL_ERROR,
    LEVEL_WARNING,
    LEVEL_INFO,
    LEVEL_DEBUG
} SDFLogLevel;

// sdf log message
void sdf_log_message(const char *func, const char *file, const int line,
                     int level, const char *type, const char *format, ...);

#define SDF_LOG(level, type, format, ...) \
        sdf_log_message(__func__, __FILE__, __LINE__, level, type, format, ##__VA_ARGS__)

#define SDF_LOG_ERROR(format, ...) SDF_LOG(LEVEL_ERROR, "ERROR", format, ##__VA_ARGS__)
#define SDF_LOG_WARING(format, ...) SDF_LOG(LEVEL_WARNING, "WARNING", format, ##__VA_ARGS__)
#define SDF_LOG_INFO(format, ...) SDF_LOG(LEVEL_INFO, "INFO", format, ##__VA_ARGS__)
#define SDF_LOG_DEBUG(format, ...) SDF_LOG(LEVEL_DEBUG, "DEBUG", format, ##__VA_ARGS__)
#endif //SDF_LOG_H
