package com.jkojote.rsa.bigint;

import com.jkojote.rsa.util.Pointer;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import static java.math.BigInteger.ZERO;

public class BigIntRsa {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Charset CHARSET = Charset.defaultCharset();

    private static BigInteger MINUS_ONE = BigInteger.valueOf(-1);

    public static void generateKeys(Pointer<BigIntKey> privateKey, Pointer<BigIntKey> publicKey, BigInteger[] primeNumbers) {
        var p = new Pointer<BigInteger>();
        var q = new Pointer<BigInteger>();
        BigInteger n, lmn, e, d;

        do {
            selectPrimes(primeNumbers, p, q);
            n = p.val.multiply(q.val);
            lmn = lcm(p.val.subtract(ONE), q.val.subtract(ONE));
            e = coprimeBrute(lmn);
            d = modInverse(e, lmn);
        } while (e.equals(MINUS_ONE) || d.equals(MINUS_ONE));

        privateKey.val = new BigIntKey(n, e);
        publicKey.val = new BigIntKey(n, d);
    }

    public static BigInteger[] encrypt(String message, BigIntKey publicKey) {
        var bytes = message.getBytes(CHARSET);
        var encryptedBytes = new BigInteger[bytes.length];
        var modulus = publicKey.getModulus();
        var exponent = publicKey.getExponent();
        for (var i = 0; i < bytes.length; i++) {
            encryptedBytes[i] = modExp(BigInteger.valueOf(bytes[i]), exponent, modulus);
        }
        return encryptedBytes;
    }

    public static String decrypt(BigInteger[] message, BigIntKey privateKey) {
        var decryptedBytes = new byte[message.length];
        var modulus = privateKey.getModulus();
        var exponent = privateKey.getExponent();
        for (var i = 0; i < message.length; i++) {
            decryptedBytes[i] = modExp(message[i], exponent, modulus).byteValue();
        }
        return new String(decryptedBytes, CHARSET);
    }

    private static BigInteger modExp(BigInteger n, BigInteger exp, BigInteger mod) {
        var i = ONE;
        for (var k = ZERO; k.compareTo(exp) < 0; k = k.add(ONE)) {
            i = i.multiply(n).mod(mod);
        }
        return i;
    }

    private static BigInteger modInverse(BigInteger a, BigInteger m) {
        for (var x = ONE; x.compareTo(m) < 0; x = x.add(ONE)) {
            if (a.multiply(x).mod(m).equals(ONE)) {
                return x;
            }
        }
        return MINUS_ONE;
    }

    private static BigInteger coprimeBrute(BigInteger a) {
        for (var i = TWO; i.compareTo(a) < 0; i = i.add(ONE)) {
            if (i.gcd(a).equals(ONE)) {
                return i;
            }
        }
        return MINUS_ONE;
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b.divide(a.gcd(b)));
    }

    private static void selectPrimes(BigInteger[] primes, Pointer<BigInteger> a, Pointer<BigInteger> b) {
        a.val = nextPrime(primes);
        do {
            b.val = nextPrime(primes);
        } while (a.val.equals(b.val));
    }

    private static BigInteger nextPrime(BigInteger[] primes) {
        return primes[Math.abs(SECURE_RANDOM.nextInt()) % primes.length];
    }
}