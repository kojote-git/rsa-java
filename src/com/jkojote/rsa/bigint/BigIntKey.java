package com.jkojote.rsa.bigint;

import java.math.BigInteger;

public class BigIntKey {
    private BigInteger modulus;
    private BigInteger exponent;

    public BigIntKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }
}
