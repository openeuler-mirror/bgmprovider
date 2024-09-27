package org.openeuler.sdf.provider;

import java.util.Locale;

public class SDFPlatformDependent {
    private static final String NORMALIZED_ARCH = normalizeArch(System.getProperty("os.arch", ""));
    private static final String NORMALIZED_OS = normalizeOs(System.getProperty("os.name", ""));

    private static String normalize(String value) {
        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }

    private static String normalizeArch(String value) {
        value = normalize(value);
        if (value.matches("^(x8664|amd64|ia32e|em64t|x64)$")) {
            return "x86_64";
        }
        if ("aarch64".equals(value)) {
            return "aarch64";
        }
        return "unknown";
    }

    private static String normalizeOs(String value) {
        value = normalize(value);
        if (value.startsWith("linux")) {
            return "linux";
        }
        return "unknown";
    }

    static String normalizedArch() {
        return NORMALIZED_ARCH;
    }

    static String normalizedOs() {
        return NORMALIZED_OS;
    }

}
