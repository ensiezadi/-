package Ex3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;

public class RSA {

    private Util util;
    private myPQ dots;
    BigInteger n;
    BigInteger phi;

    public RSA(){
        util = new Util();
        dots = util.getPQ();
        // 获取p和q的乘积
        n = dots.getP().multiply(dots.getQ());
        // 计算phi = (p-1)(q-1)
        phi = dots.getP().subtract(BigInteger.ONE).multiply(dots.getQ().subtract(BigInteger.ONE));
    }

    // 生成公钥
    public myPQ getPublicKey(){
        // 生成指数exp
        BigInteger exp = util.getRelativePrime(phi);
        return new myPQ(n.toString(), exp.toString());
    }

    // 生成私钥
    public myPQ getPrivateKey(myPQ publicKey){
        // 生成指数exp
        BigInteger[] res = util.extendGCD(publicKey.getQ(), phi);
        return new myPQ(n.toString(), res[1].mod(phi).add(phi).mod(phi).toString());
    }

    // 对数值编码
    public BigInteger encode(BigInteger val, myPQ publicKey){
        // 计算加密值
        return util.quickPow(val, publicKey.getQ(), publicKey.getP());
    }

    // 对数值解码
    public BigInteger decode(BigInteger val, myPQ privateKey){
        // 计算解密值
        return util.quickPow(val, privateKey.getQ(), privateKey.getP());
    }

    // 对字符串编码
    public String encode(String val, myPQ publicKey, String pathName){
        StringBuilder sb = new StringBuilder();
        File f = new File(pathName);
        if(f.exists()){
            f.delete();
        }
        for(int i = 0; i < val.length(); i++){
            // 计算加密值
            BigInteger m = BigInteger.valueOf((long)val.charAt(i));
            BigInteger c = encode(m, publicKey);
            try(FileWriter fw = new FileWriter(pathName, true)){
                fw.write(c.toString() + "\n");
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    // 对字符串解码
    public String decode(String pathName, myPQ privateKey){
        StringBuilder sb = new StringBuilder();
        try(FileReader f = new FileReader(new File(pathName));
            BufferedReader br = new BufferedReader(f)){
            String line;
            while((line = br.readLine()) != null){
                BigInteger c = new BigInteger(line);
                BigInteger m = decode(c, privateKey);
                sb.append((char)m.intValue());
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return sb.toString();
    }
}
