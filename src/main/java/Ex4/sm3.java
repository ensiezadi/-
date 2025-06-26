package Ex4;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SM3 哈希算法的正确实现.
 * 修正了压缩函数中的核心迭代逻辑。
 */
public class sm3 {

    private static final String ENCODING = StandardCharsets.UTF_8.name();

    // 初始IV向量
    private static final int[] IV = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

    // 常量Tj
    private static final int[] T = {0x79cc4519, 0x7a879d8a};

    /**
     * 对字符串进行SM3哈希计算
     * @param input 输入字符串
     * @return 32字节的哈希值（以十六进制字符串表示）
     */
    public static String sm3Hash(String input) {
        try {
            byte[] hashBytes = hash(input.getBytes(ENCODING));
            return bytesToHex(hashBytes);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }

    /**
     * SM3 哈希算法核心，对字节数组进行哈希。
     * @param srcData 待哈希的字节数组
     * @return 32字节(256位)的哈希结果
     */
    public static byte[] hash(byte[] srcData) {
        // 1. 消息填充
        byte[] padded = pad(srcData);
        // 2. 初始化哈希值 (IV)
        int[] V = Arrays.copyOf(IV, IV.length);
        // 3. 分块迭代压缩
        int numBlocks = padded.length / 64;
        for (int i = 0; i < numBlocks; i++) {
            byte[] block = Arrays.copyOfRange(padded, i * 64, (i + 1) * 64);
            V = compress(V, block);
        }
        // 4. 将int[]结果转换为byte[]
        return intsToBytes(V);
    }

    /**
     * 对消息进行填充，使其长度为512位的倍数。
     * 填充规则: 1个'1'比特 + k个'0'比特 + 64比特的消息长度。
     */
    private static byte[] pad(byte[] message) {
        long messageLengthBits = message.length * 8L;
        int k = (448 - (message.length * 8 + 1) % 512 + 512) % 512;
        k /= 8;

        byte[] padded = new byte[message.length + 1 + k + 8];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte) 0x80;

        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) (messageLengthBits >>> (i * 8));
        }
        return padded;
    }

    /**
     * SM3 压缩函数
     * @param V 上一轮的哈希值
     * @param block 当前的消息块 (512位)
     * @return 更新后的哈希值
     */
    private static int[] compress(int[] V, byte[] block) {
        int[] W = new int[68];
        int[] W_ = new int[64];

        // 将512位消息块B划分为16个字W0, W1, ..., W15
        for (int i = 0; i < 16; i++) {
            W[i] = (block[i * 4] & 0xFF) << 24 |
                    (block[i * 4 + 1] & 0xFF) << 16 |
                    (block[i * 4 + 2] & 0xFF) << 8 |
                    (block[i * 4 + 3] & 0xFF);
        }

        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; j++) {
            W_[j] = W[j] ^ W[j + 4];
        }

        int A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
        int SS1, SS2, TT1, TT2;

        for (int j = 0; j < 64; j++) {
            // SS1 <- rotl( (rotl(A,12) + E + rotl(Tj,j) ), 7)
            SS1 = rotl(rotl(A, 12) + E + rotl(T[j < 16 ? 0 : 1], j), 7);
            // SS2 <- SS1 xor rotl(A,12)
            SS2 = SS1 ^ rotl(A, 12);
            // TT1 <- FFj(A,B,C) + D + SS2 + W'j
            TT1 = FFj(A, B, C, j) + D + SS2 + W_[j];
            // TT2 <- GGj(E,F,G) + H + SS1 + Wj
            TT2 = GGj(E, F, G, j) + H + SS1 + W[j];

            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
        }

        int[] result = new int[8];
        result[0] = V[0] ^ A;
        result[1] = V[1] ^ B;
        result[2] = V[2] ^ C;
        result[3] = V[3] ^ D;
        result[4] = V[4] ^ E;
        result[5] = V[5] ^ F;
        result[6] = V[6] ^ G;
        result[7] = V[7] ^ H;
        return result;
    }

    private static int FFj(int X, int Y, int Z, int j) {
        return j < 16 ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
    }

    private static int GGj(int X, int Y, int Z, int j) {
        return j < 16 ? (X ^ Y ^ Z) : ((X & Y) | (~X & Z));
    }

    private static int P0(int X) {
        return X ^ rotl(X, 9) ^ rotl(X, 17);
    }

    private static int P1(int X) {
        return X ^ rotl(X, 15) ^ rotl(X, 23);
    }

    // 32位循环左移
    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    // 将int数组转换为byte数组
    private static byte[] intsToBytes(int[] arr) {
        byte[] res = new byte[arr.length * 4];
        for (int i = 0; i < arr.length; i++) {
            res[i * 4] = (byte) (arr[i] >>> 24);
            res[i * 4 + 1] = (byte) (arr[i] >>> 16);
            res[i * 4 + 2] = (byte) (arr[i] >>> 8);
            res[i * 4 + 3] = (byte) arr[i];
        }
        return res;
    }

    // 将字节数组转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
