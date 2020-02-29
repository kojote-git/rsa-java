package com.jkojote.rsa;

import com.jkojote.rsa.util.Pointer;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;

public class Rsa {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Charset CHARSET = Charset.defaultCharset();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final int ALPHABET_SIZE = 0xFF;

    public static void generateKeys(Pointer<Key> publicKey, Pointer<Key> privateKey, long[] primes) {
        var p = new Pointer<Long>();
        var q = new Pointer<Long>();
        long n, lmn, e = -1, d = -1;

        do {
            selectPrimes(primes, p, q);
            n = p.val * q.val;

            /*
             * I noticed an interesting thing.
             * If n (which is a modulus) is less than the size of the alphabet
             * it breaks the encryption/decryption process.
             *
             * For example:
             * 1. Lets take the number 72 to encrypt.
             * 2. Suppose the modulus is 46.
             *
             * Now, the fact is that the maximum encrypted value is 46.
             * because during encryption we take the modulus which is 46.
             *
             * The same true for decryption as it also takes the modulus.
             * But this time, we cannot get 72 back.
             * Therefore, we need to specify minimum value of the modulus
             * to avoid such problems.
             *
             * By default, it is 0xFF which is the maximum value of byte
             * since we encrypt/decrypt bytes.
             *
             */
            if (n < ALPHABET_SIZE) {
                continue;
            }

            lmn = lcm(p.val - 1, q.val - 1);
            e = coprimeBrute(lmn);
            d = modInverse(e, lmn);
        } while (e == -1 || d == -1);

        publicKey.val = new Key(n, e);
        privateKey.val = new Key(n, d);
    }

    public static long[] encrypt(String message, Key publicKey) {
        var bytes = message.getBytes(CHARSET);
        var encryptedMessage = new long[bytes.length];
        var exponent = publicKey.getExponent();
        var modulus = publicKey.getModulus();
        for (var i = 0; i < bytes.length; i++) {
            encryptedMessage[i] = modExp(bytes[i], exponent, modulus);
        }
        return encryptedMessage;
    }

    public static String decrypt(long[] encryptedMessage, Key privateKey) {
        var bytes = new byte[encryptedMessage.length];
        var exponent = privateKey.getExponent();
        var modulus = privateKey.getModulus();
        for (var i = 0; i < bytes.length; i++) {
            var decryptedByte = modExp(encryptedMessage[i], exponent, modulus) & 0xFF;
            bytes[i] = (byte) decryptedByte;
        }
        return new String(bytes, CHARSET);
    }

    public static String encryptToString(String message, Key publicKey) {
        return convertLongArrayToBase64EncodedString(encrypt(message, publicKey));
    }

    public static String decryptFromString(String encryptedMessage, Key privateKey) {
        var encryptedMessageAsLongArray = convertBase64EncodedStringToLongArray(encryptedMessage);
        return decrypt(encryptedMessageAsLongArray, privateKey);
    }

    private static String convertLongArrayToBase64EncodedString(long[] array) {
        var bytes = new byte[array.length * 8];
        for (int i = 0; i < array.length; i++) {
            var longAsByteArray = longToBytes(array[i]);
            System.arraycopy(longAsByteArray, 0, bytes, i * 8, 8);
        }
        return new String(BASE64_ENCODER.encode(bytes), CHARSET);
    }

    private static long[] convertBase64EncodedStringToLongArray(String string) {
        var bytes = BASE64_DECODER.decode(string.getBytes(CHARSET));
        var array = new long[bytes.length / 8];
        for (int i = 0; i < array.length; i++) {
            array[i] = bytesChunkToLong(bytes, i * 8);
        }
        return array;
    }

    private static byte[] longToBytes(long number) {
        var bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) ((number >>> ((7 - i) * 8)) & 0xFF);
        }
        return bytes;
    }

    private static long bytesChunkToLong(byte[] bytes, int pos) {
        var longNumber = 0L;
        for (int i = pos; i < pos + 8; i++) {
            long shift = (7 - (i - pos)) * 8;
            longNumber |= ((bytes[i] & 0xFFL) << shift);
        }
        return longNumber;
    }

    private static long modInverse(long a, long m) {
        for (var x = 2; x < m; x++) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        return -1;
    }

    private static long coprimeBrute(long a) {
        for (long i = 2; i < a; i++) {
            if (gcd(i, a) == 1) {
                return i;
            }
        }
        return -1;
    }

    private static long lcm(long a, long b) {
        return a * (b / gcd(a, b));
    }

    private static void selectPrimes(long[] primes, Pointer<Long> a, Pointer<Long> b) {
        a.val = nextPrime(primes);
        do {
            b.val = nextPrime(primes);
        } while (a.val.equals(b.val));
    }

    private static long nextPrime(long[] primes) {
        return primes[Math.abs(SECURE_RANDOM.nextInt()) % primes.length];
    }

    private static long gcd(long a, long b) {
        while (b > 0) {
            long temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    static long modExp(long n, long exp, long mod) {
        long i  = 1;
        for (var k = 0; k < exp; k++) {
            i = (i * n) % mod;
        }
        return i;
    }
}
