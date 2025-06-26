package Ex5;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import Ex4.sha2;
import Ex4.sm3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class hmac {

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

    // HMAC 块大小 (B), 对于SHA-256是 64 字节
    private static final int HMAC_BLOCK_SIZE = 64;
    // HMAC 内部和外部填充常量
    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5c;

    public static void main(String[] args) throws Exception {
        // --- HMAC-SHA256 测试 ---
        System.out.println("--- HMAC-SHA256 Test ---");
        String key_sha256 = "mysecretkey";
        String message_sha256 = "The quick brown fox jumps over the lazy dog";

        String myHmacResult = hmacSha256(key_sha256, message_sha256);

        // 使用Java JCE标准库进行对比验证
        Mac macSha256 = Mac.getInstance("HmacSHA256");
        macSha256.init(new SecretKeySpec(key_sha256.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] jceHmacBytes = macSha256.doFinal(message_sha256.getBytes(StandardCharsets.UTF_8));
        String jceHmacResult = bytesToHex(jceHmacBytes);

        System.out.println("Message           : " + message_sha256);
        System.out.println("Key               : " + key_sha256);
        System.out.println("My HMAC-SHA256    : " + myHmacResult);
        System.out.println("JCE HMAC-SHA256   : " + jceHmacResult);
        System.out.println("Is Correct        : " + myHmacResult.equals(jceHmacResult));
        System.out.println();

        // --- HMAC-SM3 测试 ---
        // 注册Bouncy Castle作为安全提供者
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("--- HMAC-SM3 Test ---");
        String key_sm3 = "this-is-a-secret-key";
        String message_sm3 = "你好，世界！Welcome to SM3.";

        String myHmacSm3Result = hmacSm3(key_sm3, message_sm3);

        // 使用 Bouncy Castle 的实现进行对比验证
        Mac macSm3 = Mac.getInstance("HmacSM3");
        macSm3.init(new SecretKeySpec(key_sm3.getBytes(StandardCharsets.UTF_8), "HmacSM3"));
        byte[] bcHmacBytes = macSm3.doFinal(message_sm3.getBytes(StandardCharsets.UTF_8));
        String bcHmacResult = bytesToHex(bcHmacBytes);


        System.out.println("Message           : " + message_sm3);
        System.out.println("Key               : " + key_sm3);
        System.out.println("My HMAC-SM3       : " + myHmacSm3Result);
        System.out.println("BC HMAC-SM3       : " + bcHmacResult);
        System.out.println("Is Correct        : " + myHmacSm3Result.equals(bcHmacResult));

    }

    /**
     * 使用 HMAC-SHA256 计算消息摘要
     *
     * @param key 密钥
     * @param message 消息
     * @return 16进制格式的HMAC摘要
     */
    public static String hmacSha256(String key, String message) {
        return hmac(key.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8), "Sha2");
    }

    public static String hmacSm3(String key, String message) {
        return hmac(key.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8), "Sm3");
    }

    /**
     * 使用 HMAC-SHA256 计算消息摘要
     *
     * @param keyBytes 密钥字节数组
     * @param messageBytes 消息字节数组
     * @return 16进制格式的HMAC摘要
     */
    public static String hmac(byte[] keyBytes, byte[] messageBytes, String type) {

        // 1. 处理密钥 K'
        byte[] processedKey = new byte[HMAC_BLOCK_SIZE];
        if (keyBytes.length > HMAC_BLOCK_SIZE) {
            // 如果密钥太长，先哈希
            processedKey = type.equals("Sm3") ? sm3.hash(keyBytes) : sha2.performHash(keyBytes);
        } else {
            // 如果密钥太短，用0填充
            System.arraycopy(keyBytes, 0, processedKey, 0, keyBytes.length);
        }

        // 2. 准备 o_key_pad 和 i_key_pad
        byte[] o_key_pad = new byte[HMAC_BLOCK_SIZE];
        byte[] i_key_pad = new byte[HMAC_BLOCK_SIZE];
        for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
            o_key_pad[i] = (byte) (processedKey[i] ^ OPAD);
            i_key_pad[i] = (byte) (processedKey[i] ^ IPAD);
        }

        // 3. 计算内部哈希 H(K' ⊕ ipad || m)
        byte[] innerHashInput = new byte[i_key_pad.length + messageBytes.length];
        System.arraycopy(i_key_pad, 0, innerHashInput, 0, i_key_pad.length);
        System.arraycopy(messageBytes, 0, innerHashInput, i_key_pad.length, messageBytes.length);
        byte[] innerHashResult = type.equals("Sm3") ? sm3.hash(innerHashInput) : sha2.performHash(innerHashInput);

        // 4. 计算外部哈希 H(K' ⊕ opad || H(...))
        byte[] outerHashInput = new byte[o_key_pad.length + innerHashResult.length];
        System.arraycopy(o_key_pad, 0, outerHashInput, 0, o_key_pad.length);
        System.arraycopy(innerHashResult, 0, outerHashInput, o_key_pad.length, innerHashResult.length);
        byte[] finalHash = type.equals("Sm3") ? sm3.hash(outerHashInput) : sha2.performHash(outerHashInput);

        // 5. 返回16进制结果
        return bytesToHex(finalHash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

