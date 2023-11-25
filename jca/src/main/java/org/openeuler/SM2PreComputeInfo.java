package org.openeuler;

public class SM2PreComputeInfo {
        private SM2P256V1Point[] lookupTable;
        private SM2P256V1Point offset;
        private int width;

        public SM2P256V1Point[] getLookupTable() {
            return lookupTable;
        }

        public void setLookupTable(SM2P256V1Point[] lookupTable) {
            this.lookupTable = lookupTable;
        }

        public SM2P256V1Point getOffset() {
            return offset;
        }

        public void setOffset(SM2P256V1Point offset) {
            this.offset = offset;
        }

        public int getWidth() {
            return width;
        }

        public void setWidth(int width) {
            this.width = width;
        }
    }