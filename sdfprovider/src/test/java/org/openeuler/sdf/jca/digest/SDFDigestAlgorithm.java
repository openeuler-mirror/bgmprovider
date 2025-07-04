package org.openeuler.sdf.jca.digest;

enum SDFDigestAlgorithm {
        SM3("SM3", true, null, "hello world",
                "44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88", 32),
        MD5("MD5", false, null, "hello world",
                "5EB63BBBE01EEED093CB22BB8F5ACDC3", 16),
        SHA1("SHA-1", false, new String[]{"SHA", "1.3.14.3.2.26"}, "hello world",
                "2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED", 20),
        SHA224("SHA-224", false, new String[]{"2.16.840.1.101.3.4.2.4"}, "hello world",
                "2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B", 28),
        SHA256("SHA-256", false, new String[]{"2.16.840.1.101.3.4.2.1"}, "hello world",
                "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", 32),
        SHA384("SHA-384", false, new String[]{"2.16.840.1.101.3.4.2.2"}, "hello world",
                "FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3" +
                        "E417CB71CE646EFD0819DD8C088DE1BD", 48),
        SHA512("SHA-512", false, new String[]{"2.16.840.1.101.3.4.2.3"}, "hello world",
                "309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F" +
                        "989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F", 64);

        final String algoName;
        final boolean isSM;
        final String[] algoAliases;
        final String plainText;
        final String digestValue;
        final int digestLen;

        SDFDigestAlgorithm(String algoName, boolean isSM, String[] algoAliases,
                           String plainText, String digestValue, int digestLen) {
            this.algoName = algoName;
            this.isSM = isSM;
            this.algoAliases = algoAliases;
            this.plainText = plainText;
            this.digestValue = digestValue;
            this.digestLen = digestLen;
        }
    }