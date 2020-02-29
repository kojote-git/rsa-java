package com.jkojote.rsa;

public class Key {
    private long modulus;
    private long exponent;

    public Key(long modulus, long exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public long getExponent() {
        return exponent;
    }

    public long getModulus() {
        return modulus;
    }

    @Override
    public String toString() {
        return "{" + "modulus=" + modulus + ", exponent=" + exponent + "}";
    }
}
