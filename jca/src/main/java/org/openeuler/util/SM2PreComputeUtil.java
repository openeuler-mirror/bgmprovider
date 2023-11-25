package org.openeuler.util;

import org.openeuler.SM2P256V1Point;
import org.openeuler.SM2Point;
import org.openeuler.SM2PreComputeInfo;

import java.security.spec.ECPoint;

public class SM2PreComputeUtil {

    static SM2PreComputeInfo getPreComputeInfo(ECPoint ecPoint, int fieldSize) {
        SM2P256V1Point sm2P256V1Point = new SM2P256V1Point(ecPoint);
        if (ecPoint instanceof SM2Point) {
            return getSM2PointPreComputeInfo((SM2Point) ecPoint, fieldSize, sm2P256V1Point);
        }
        return createPreComputeInfo(sm2P256V1Point, fieldSize);
    }

    static SM2PreComputeInfo getSM2PointPreComputeInfo(SM2Point sm2Point, int fieldSize, SM2P256V1Point sm2P256V1Point) {
        synchronized (sm2Point) {
            SM2PreComputeInfo preComputeInfo = sm2Point.getPreComputeInfo();
            if (preComputeInfo == null) {
                preComputeInfo = createPreComputeInfo(sm2P256V1Point, fieldSize);
                sm2Point.setPreComputeInfo(preComputeInfo);
            }
        }
        return sm2Point.getPreComputeInfo();
    }

    private static SM2PreComputeInfo createPreComputeInfo(SM2P256V1Point p, int fieldSize) {
        int minWidth = fieldSize > 250 ? 6 : 5;
        int n = 1 << minWidth;

        int d = (fieldSize + minWidth - 1) / minWidth;

        SM2P256V1Point[] pow2Table = new SM2P256V1Point[minWidth + 1];
        pow2Table[0] = p;
        for (int i = 1; i < minWidth; ++i) {
            pow2Table[i] = GMUtil.timesPow2(pow2Table[i - 1], d);
        }

        // This will be the 'offset' value
        pow2Table[minWidth] = GMUtil.subtract(pow2Table[0], pow2Table[1]);

        SM2P256V1Point[] lookupTable = new SM2P256V1Point[n];
        lookupTable[0] = pow2Table[0];

        for (int bit = minWidth - 1; bit >= 0; --bit) {
            SM2P256V1Point pow2 = pow2Table[bit];

            int step = 1 << bit;
            for (int i = step; i < n; i += (step << 1)) {
                lookupTable[i] = GMUtil.add(lookupTable[i - step], pow2);
            }
        }
        SM2PreComputeInfo preComputeInfo = new SM2PreComputeInfo();
        preComputeInfo.setLookupTable(lookupTable);
        preComputeInfo.setOffset(pow2Table[minWidth]);
        preComputeInfo.setWidth(minWidth);
        return preComputeInfo;
    }
}
