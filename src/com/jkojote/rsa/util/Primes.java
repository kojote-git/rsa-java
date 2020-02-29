package com.jkojote.rsa.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

import static java.math.BigInteger.ONE;

public class Primes {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static BigInteger[] generatePrimeNumbersAsBigIntegers(int bitLength, int number) {
        var primes = new BigInteger[number];

        for (int i = 0; i < number; i++) {
            var prime = nextPossiblePrime(bitLength);
            while (!isPrime(prime) || contains(primes, prime)) {
                prime = nextPossiblePrime(bitLength);
            }
            primes[i] = prime;
        }
        return primes;
    }

    public static long[] generatePrimeNumbers(int length) {
        var primes = new long[length];

        for (int i = 0; i < length; i++) {
            var prime = SECURE_RANDOM.nextLong();
            while (!isPrime(prime) || contains(primes, prime)) {
                prime = SECURE_RANDOM.nextLong();
            }
            primes[i] = prime;
        }
        return primes;
    }


    private static BigInteger nextPossiblePrime(int bitLength) {
        return new BigInteger(bitLength, 32, SECURE_RANDOM);
    }

    private static boolean isPrime(BigInteger number) {
        var numberSqrt = number.sqrt();
        for (var i = BigInteger.TWO; i.compareTo(numberSqrt) < 0; i = i.add(ONE)) {
            if (number.mod(i).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPrime(long number) {
        var numberSqrt = Math.sqrt(number);
        for (var i = 2; i < numberSqrt; i++) {
            if (number % i == 0) {
                return false;
            }
        }
        return true;
    }

    private static <T> boolean contains(T[] array, T element) {
        for (var e : array) {
            if (Objects.equals(e, element)) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(long[] array, long element) {
        for (var e : array) {
            if (e == element) {
                return true;
            }
        }
        return false;
    }
}
