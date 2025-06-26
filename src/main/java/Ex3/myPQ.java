package Ex3;

import java.math.BigInteger;

public class myPQ {
    final private BigInteger p;
    final private BigInteger q;

    public myPQ(String p, String q){
        this.p = new BigInteger(p);
        this.q = new BigInteger(q);
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }
}
