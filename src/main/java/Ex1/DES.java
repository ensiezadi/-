package Ex1;

import java.util.Arrays;

class DES {

    // --- DES常量表 ---

    // 初始置换表 IP
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };

    // 逆初始置换表 IP^-1
    private static final int[] FINAL_IP = {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    };

    // 扩展置换表 E
    private static final int[] E = {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };

    // P置换表
    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26,
            5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
    };

    // S盒
    private static final int[][] S_BOX = {{
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    }, {
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    }, {
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    }, {
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    }, {
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    }, {
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    }, {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    }, {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }};

    // --- 密钥生成常量表 ---

    // PC-1 置换选择表
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };

    // PC-2 置换选择表
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    // 每轮循环左移位数
    private static final int[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    // 存储16轮的48位子密钥
    private int[][] subKeys = new int[16][48];

    public DES(byte[] key) {
        if (key.length != 8) {
            throw new IllegalArgumentException("长度必须是8字节");
        }
        int[] keyBits = bytesToBits(key, 64);
        generateSubKeys(keyBits);
    }

    /**
     * 加密一个8字节的数据块
     * @param plainText 8字节的明文块
     * @return 8字节的密文块
     */
    public byte[] encrypt(byte[] plainText) {
        int[] plainBits = bytesToBits(plainText, 64);
        int[] cipherBits = process(plainBits, false); // 加密，isDecrypt=false
        return bitsToBytes(cipherBits, 8);
    }

    /**
     * 解密一个8字节的数据块
     * @param cipherText 8字节的密文块
     * @return 8字节的明文块
     */
    public byte[] decrypt(byte[] cipherText) {
        int[] cipherBits = bytesToBits(cipherText, 64);
        int[] plainBits = process(cipherBits, true); // 解密，isDecrypt=true
        return bitsToBytes(plainBits, 8);
    }

    // --- 核心加解密流程 ---

    private int[] process(int[] dataBits, boolean isDecrypt) {
        // 1. 初始置换 IP
        int[] permutedBits = permute(dataBits, IP);

        // 2. 16轮Feistel网络
        int[] left = Arrays.copyOfRange(permutedBits, 0, 32);
        int[] right = Arrays.copyOfRange(permutedBits, 32, 64);

        for (int i = 0; i < 16; i++) {
            int[] subKey = isDecrypt ? subKeys[15 - i] : subKeys[i]; // 解密时逆序使用子密钥

            int[] oldLeft = left;
            left = right;
            right = xor(oldLeft, f(right, subKey));
        }

        // 3. 合并左右两半，并进行最后一次交换（因为循环多了一次交换）
        int[] combined = new int[64];
        System.arraycopy(right, 0, combined, 0, 32); // 注意这里是先right后left
        System.arraycopy(left, 0, combined, 32, 32);

        // 4. 逆初始置换 IP^-1
        return permute(combined, FINAL_IP);
    }

    // --- 子密钥生成 ---

    private void generateSubKeys(int[] key64) {
        // PC-1置换，64位变56位
        int[] key56 = permute(key64, PC1);

        // 分成左右两半 C0, D0
        int[] c = Arrays.copyOfRange(key56, 0, 28);
        int[] d = Arrays.copyOfRange(key56, 28, 56);

        for (int i = 0; i < 16; i++) {
            // 循环左移
            c = leftShift(c, SHIFTS[i]);
            d = leftShift(d, SHIFTS[i]);

            // 合并C, D
            int[] combined = new int[56];
            System.arraycopy(c, 0, combined, 0, 28);
            System.arraycopy(d, 0, combined, 28, 28);

            // PC-2置换，56位变48位，得到当前轮的子密钥
            subKeys[i] = permute(combined, PC2);
        }
    }

    // --- Feistel轮函数 F ---

    private int[] f(int[] right, int[] subKey) {
        // 1. 扩展置换 E (32 -> 48)
        int[] expanded = permute(right, E);
        // 2. 与子密钥异或
        int[] xored = xor(expanded, subKey);
        // 3. S盒代换 (48 -> 32)
        int[] substituted = sBoxSubstitute(xored);
        // 4. P置换
        return permute(substituted, P);
    }

    // --- 辅助函数 ---

    private int[] sBoxSubstitute(int[] data48) {
        int[] data32 = new int[32];
        for (int i = 0; i < 8; i++) {
            int[] block6 = Arrays.copyOfRange(data48, i * 6, (i + 1) * 6);
            int row = 2 * block6[0] + block6[5];
            int col = 8 * block6[1] + 4 * block6[2] + 2 * block6[3] + block6[4];
            int val = S_BOX[i][row * 16 + col];

            // 将S盒输出的整数转换为4位二进制
            for (int j = 3; j >= 0; j--) {
                data32[i * 4 + j] = val % 2;
                val /= 2;
            }
        }
        return data32;
    }

    private int[] permute(int[] bits, int[] table) {
        int[] result = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            result[i] = bits[table[i] - 1]; // 表中的索引从1开始
        }
        return result;
    }

    private int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    private int[] leftShift(int[] bits, int n) {
        int[] result = new int[bits.length];
        System.arraycopy(bits, n, result, 0, bits.length - n);
        System.arraycopy(bits, 0, result, bits.length - n, n);
        return result;
    }

    private int[] bytesToBits(byte[] bytes, int bitLength) {
        int[] bits = new int[bitLength];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (bytes[i] >> (7 - j)) & 1;
            }
        }
        return bits;
    }

    private byte[] bitsToBytes(int[] bits, int byteLength) {
        byte[] bytes = new byte[byteLength];
        for (int i = 0; i < bytes.length; i++) {
            int val = 0;
            for (int j = 0; j < 8; j++) {
                val = (val << 1) | bits[i * 8 + j];
            }
            bytes[i] = (byte) val;
        }
        return bytes;
    }
}