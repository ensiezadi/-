package Ex3;

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Util {

    //  取最大公约数
    // 被除数 -> 除数 -> 余数,最后一轮循环已经除尽，到终止循环时余数为0就是作为输入的除数。
    public BigInteger Gcd(BigInteger a, BigInteger b){
        if(b.equals(BigInteger.ZERO)){
            return a;
        }
        return Gcd(b, a.mod(b));
    }

    // 实现快速幂模运算
    public BigInteger quickPow(BigInteger input, BigInteger power, BigInteger module){
        BigInteger res = BigInteger.ONE;
        while(!power.equals(BigInteger.ZERO)){
            // 假如最低位的二进制表示是1，那么表明有当前的一个基数，需要将结果乘上并取模
            if(power.and(BigInteger.ONE).equals(BigInteger.ONE)){
               res =  res.multiply(input).mod(module);
            }
            // 将基数自增，幂数自减以保证基数相乘正确，幂数正常移动。
            input = input.multiply(input).mod(module);
            power = power.shiftRight(1);
        }
        return  res;
    }

    // 实现扩展欧几里得算法取乘法逆元
    public BigInteger[] extendGCD(BigInteger a, BigInteger b){
        BigInteger[] res = new BigInteger[3];
        // 递归终止条件： a * 1 + b * 0 = a;
        if(b.equals(BigInteger.ZERO)){
            res[0] = a;
            res[1] = BigInteger.ONE;
            res[2] = BigInteger.ZERO;
        }else {
            BigInteger[] temp = extendGCD(b, a.mod(b));
            res[0] = temp[0];
            res[1] = temp[2];
            // temp[1]存的是回溯的x，当前的a减掉递归回来的最大公约数倍数
            res[2] = temp[1].subtract(a.divide(b).multiply(temp[2]));
        }
        return res;
    }

    // 给定一个数，得到它的素数
    public BigInteger getRelativePrime(BigInteger a){
        BigInteger res;
        while(true){
            res = BigInteger.probablePrime(200,new Random());
            if(Gcd(a, res).equals(BigInteger.ONE)){
                return res;
            }
        }
    }

    // 生成一对大素数
    public myPQ getPQ() {
        List<BigInteger> primes = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader("src/main/resources/prime.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] numbers = line.split("\\s+|\\t+");
                for (String num : numbers) {
                    primes.add(new BigInteger(num));
                }
            }
            Random random = new Random();
            BigInteger p = primes.get(random.nextInt(primes.size()));
            BigInteger q;
            do {
                q = primes.get(random.nextInt(primes.size()));
            } while (p.equals(q));
            return new myPQ(p.toString(), q.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
