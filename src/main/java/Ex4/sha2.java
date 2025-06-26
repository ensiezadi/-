package Ex4;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class sha2 {

    // 8个初始哈希值 (SHA-256)
    private static final int[] H = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // 64个常量 (SHA-256)
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    public static String encrypt(String msg) {
        return encrypt(msg.getBytes(StandardCharsets.UTF_8));
    }

    public static String encryptFile(String filePath) throws IOException {
        try (InputStream fis = new FileInputStream(filePath); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, n);
            }
            return encrypt(baos.toByteArray());
        }
    }

    public static String encrypt(byte[] bytes) {
        byte[] hash = performHash(bytes);
        return bytesToHex(hash);
    }

    public static byte[] performHash(byte[] messageBytes) {
        int[] h = Arrays.copyOf(H, H.length);

        // 1. 消息填充 (Padding)
        long originalLengthBits = messageBytes.length * 8L;
        int paddingBytes = (56 - (messageBytes.length % 64) + 64) % 64;
        if (paddingBytes == 0) {
            paddingBytes = 64;
        }

        byte[] paddedMessage = new byte[messageBytes.length + paddingBytes + 8];
        System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
        paddedMessage[messageBytes.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            paddedMessage[paddedMessage.length - 1 - i] = (byte) (originalLengthBits >>> (i * 8));
        }

        // 2. 分块处理
        int numBlocks = paddedMessage.length / 64;
        for (int i = 0; i < numBlocks; i++) {
            int[] m = new int[16];
            for (int j = 0; j < 16; j++) {
                int blockOffset = i * 64 + j * 4;
                m[j] = (paddedMessage[blockOffset] & 0xFF) << 24
                        | (paddedMessage[blockOffset + 1] & 0xFF) << 16
                        | (paddedMessage[blockOffset + 2] & 0xFF) << 8
                        | (paddedMessage[blockOffset + 3] & 0xFF);
            }
            //  3. 核心压缩计算
            calculate_sha_256(h, m);
        }

        // 4. 将最终的h0...转换成字节数组
        byte[] hashResult = new byte[32];
        for (int i = 0; i < 8; i++) {
            hashResult[i * 4] = (byte) (h[i] >>> 24);
            hashResult[i * 4 + 1] = (byte) (h[i] >>> 16);
            hashResult[i * 4 + 2] = (byte) (h[i] >>> 8);
            hashResult[i * 4 + 3] = (byte) h[i];
        }
        return hashResult;
    }

    private static void calculate_sha_256(int[] h, int[] m) {
        int[] w = get64W(m);
        int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], H_ = h[7];

        for (int i = 0; i < 64; i++) {
            int S1 = big_sigma1(e);
            int ch_val = ch(e, f, g);
            int temp1 = H_ + S1 + ch_val + K[i] + w[i];
            int S0 = big_sigma0(a);
            int maj_val = maj(a, b, c);
            int temp2 = S0 + maj_val;

            H_ = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += H_;
    }

    private static int[] get64W(int[] m) {
        int[] w = new int[64];
        System.arraycopy(m, 0, w, 0, 16);
        for (int i = 16; i < 64; i++) {
            int s0 = small_sigma0(w[i - 15]);
            int s1 = small_sigma1(w[i - 2]);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        return w;
    }

    private static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static int big_sigma0(int x) {
        return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
    }

    private static int big_sigma1(int x) {
        return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
    }

    private static int small_sigma0(int x) {
        return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >>> 3);
    }

    private static int small_sigma1(int x) {
        return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >>> 10);
    }

    private static int rightRotate(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
