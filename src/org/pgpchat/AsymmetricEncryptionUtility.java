package org.pgpchat; /** NIS Assignment: Asymmetric Encryption Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class AsymmetricEncryptionUtility {
    private static final String RSA = "RSA"; //RSA Algorithm used
    private static final String BC = "BC";
    private static final String RSA_CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * Constructor
     */
    private AsymmetricEncryptionUtility(){
        init();
    }

    /**
     * Init method
     */
    private static void init(){
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generate key pair
     */
    public static KeyPair generateRSAKeys() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA, BC);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * RSA encryption
     * @param plainText Plain Text
     * @param privateKey Private Key
     * @return encrypted byte array
     * @throws Exception Exception
     */
    public static byte[] performRSAEncryption(byte[] plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText);
    }

    /**
     * RSA encryption
     * @param key Session Key
     * @param publicKey Public Key
     * @return encrypted byte array
     * @throws Exception Exception
     */
    public static byte[] performRSAKeyEncryption(SecretKey key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key.getEncoded());
    }

    /**
     * RSA decryption
     * @param encryptedSessionKey Session Key
     * @param privateKey Private Key
     * @return decrypted byte array
     * @throws Exception Exception
     */
    public static byte[] performRSAKeyDecryption(byte[] encryptedSessionKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSessionKey);
    }
  
    /**
     * RSA decryption
     * @param cipherText  Cipher Text
     * @param publicKey Public Key
     * @return decrypted byte array
     * @throws Exception Exception
     */
    public static byte[] performRSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(cipherText);
    }
}
