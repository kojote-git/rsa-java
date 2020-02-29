package com.jkojote.rsa;

import com.jkojote.rsa.util.Pointer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class Main {
    public static void main(String[] args) throws IOException {
        var primeNumbers = new long[] {
            2,	3,	 5,	  7,   11,	13,	 17,  19,  23,	29,	 31,  37,
            41,	43,	 47,  53,  59,	61,	 67,  71,  73,	79,	 83,  89,
            97,	101, 103, 107, 109, 113, 127, 131, 137,	139, 149, 151
        };
        var reader = new BufferedReader(new InputStreamReader(System.in));

        while (true) {
            var publicKey = new Pointer<Key>();
            var privateKey = new Pointer<Key>();
            Rsa.generateKeys(publicKey, privateKey, primeNumbers);

            System.out.print("Write a message to encrypt");
            var message = reader.readLine();
            System.out.println("Public key : " + publicKey.val);
            System.out.println("Private key: " + privateKey.val);

            var encryptedMessage = Rsa.encryptToString(message, publicKey.val);
            var decryptedMessage = Rsa.decryptFromString(encryptedMessage, privateKey.val);

            System.out.println("Encrypted message: " + encryptedMessage);
            System.out.println("Decrypted message: " + decryptedMessage);
            System.out.println();
        }

    }

    private static BigInteger[] bigIntegerArrayOf(long[] values) {
        var result = new BigInteger[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = BigInteger.valueOf(values[i]);
        }
        return result;
    }
}
