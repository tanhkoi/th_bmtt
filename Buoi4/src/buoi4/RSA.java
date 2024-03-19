package buoi4;

import java.math.BigInteger;
import java.util.Random;
import java.io.*;

public class RSA {

    // Độ dài bit của mỗi số nguyên tố
    int primeSize;
    // Hai số nguyên tố lớn phân biệt p và q
    BigInteger p, q;
    // Modulus N
    BigInteger N;
    // r = (p-1)*(q-1)
    BigInteger r;
    // Khóa công khai E và khóa riêng D
    BigInteger E, D;

    public RSA() {
    }

    public RSA(int primeSize) {
        // int primeZize = 0;
        this.primeSize = primeSize;
        generatePrimeNumbers();
        generatePublicPrivatekeys();
    }

    private void generatePrimeNumbers() {
        Random random = new Random();
        // Random random = null;
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        p = BigInteger.probablePrime(primeSize / 2, random);

        do {
            q = BigInteger.probablePrime(primeSize / 2, random);
        } while (q.compareTo(p) == 0);
    }

    private void generatePublicPrivatekeys() {
        // N = p * q
        N = p.multiply(q);
        // r = (p - 1)*(q - 1)
        r = p.subtract(BigInteger.valueOf(1));
        r = r.multiply(q.subtract(BigInteger.valueOf(1)));
        // Chọn E, số nguyên tố <= r
        do {
            E = new BigInteger(2 * primeSize, new Random());
        } while ((E.compareTo(r) != -1) || (E.gcd(r).compareTo(BigInteger.valueOf(1)) != 0));
        D = E.modInverse(r);
    }

    public BigInteger[] encrypt(String message) {
        int i;
        byte[] temp = new byte[1];
        byte[] digits = message.getBytes();
        BigInteger[] bigdigits = new BigInteger[digits.length];
        for (i = 0; i < bigdigits.length; i++) {
            temp[0] = digits[i];
            bigdigits[i] = new BigInteger(temp);
        }
        BigInteger[] encrypted = new BigInteger[bigdigits.length];
        for (i = 0; i < bigdigits.length; i++) {
            encrypted[i] = bigdigits[i].modPow(E, N);
        }
        return (encrypted);

    }

    public BigInteger[] encrypt(String message, BigInteger userD, BigInteger userN) {
        int i;
        byte[] temp = new byte[1];
        byte[] digits = message.getBytes();
        BigInteger[] bigdigits = new BigInteger[digits.length];
        for (i = 0; i < bigdigits.length; i++) {
            temp[0] = digits[i];
            bigdigits[i] = new BigInteger(temp);
        }
        BigInteger[] encrypted = new BigInteger[bigdigits.length];
        for (i = 0; i < bigdigits.length; i++) {
            encrypted[i] = bigdigits[i].modPow(userD, userN);
        }
        return (encrypted);
    }

    public String decrypt(BigInteger[] encrypted, BigInteger D, BigInteger N) {
        int i;
        BigInteger[] decrypted = new BigInteger[encrypted.length];
        for (i = 0; i < decrypted.length; i++) {
            decrypted[i] = encrypted[i].modPow(D, N);
        }
        char[] charArray = new char[decrypted.length];
        for (i = 0; i < charArray.length; i++) {
            charArray[i] = (char) (decrypted[i].intValue());
        }
        return (new String(charArray));

    }

    public BigInteger getp() {
        return (p);
    }

    public BigInteger getq() {
        return (q);
    }

    public BigInteger getr() {
        return (r);
    }

    public BigInteger getN() {
        return (N);
    }

    public BigInteger getE() {
        return (E);
    }

    public BigInteger getD() {
        return (D);
    }

    public static void main(String[] args) throws IOException {

        int primeSize = 8;
        // Generate Public and Private Keys
        RSA rsa = new RSA(primeSize);

        System.out.println("Key Size:[" + primeSize + "]");
        System.out.println("");

        System.out.println("Generated prime numbers p and q");
        System.out.println("p: [" + rsa.getp().toString(16).toUpperCase() + "]");
        System.out.println("q: [" + rsa.getq().toString(16).toUpperCase() + "]");
        System.out.println("");

        System.out.println("The public key is the pair (N, E) which will be published.");
        System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
        System.out.println("E: [" + rsa.getE().toString(16).toUpperCase() + "]");
        System.out.println("");

        System.out.println("The private key is the pair (N, D) which will be kept private.");
        System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
        System.out.println("D: [" + rsa.getD().toString(16).toUpperCase() + "]");
        System.out.println("");

        //Get message (plaintext) from user
        System.out.println("please enter message (plaintext):");
        String plaintext = (new BufferedReader(new InputStreamReader(System.in))).readLine();
        System.out.println("");

        //Encrypt Message
        BigInteger[] ciphertext = rsa.encrypt(plaintext);

        System.out.print("Ciphertext: [");
        for (int i = 0; i < ciphertext.length; i++) {
            System.out.print(ciphertext[i].toString(16).toUpperCase());
            if (i != ciphertext.length - 1) {
                System.out.print(" ");
            }
        }
        System.out.println("]");
        System.out.println("");
        RSA rsal = new RSA(8);

        String recoveredPlaintext = rsal.decrypt(ciphertext, rsa.getD(), rsa.getN());
        System.out.println("Recovered plaintext: [" + recoveredPlaintext + "]");
    }

    
}
