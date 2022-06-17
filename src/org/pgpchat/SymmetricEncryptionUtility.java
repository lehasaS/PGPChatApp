package org.pgpchat; /** NIS Assignment: Symmetric Encryption/Decryption Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class SymmetricEncryptionUtility {

    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Create symmetric key
     * @return key
     * @throws Exception Exception
     */
    public static SecretKey createAESKey() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    /**
     * Create initialisation vector
     * @return IV
     */
    public static byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector); //populates 16 bytes with cryptographic random set of bytes
        return initializationVector;
    }

    /**
     * Encrypt
     * @param plainText Plain Text
     * @param secretKey Secret Key
     * @param initializationVector Initialization Vecto
     * @return encrypted text
     * @throws Exception Exception
     */
    public static byte[] performAESEncryption(byte[] plainText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText);
    }

    /**
     * Decrypt
     * @param cipherText Cipher Text
     * @param secretKey Secret Key
     * @param initializationVector Initialization Vector
     * @return decrypted text
     * @throws Exception Exception
     */
    public static byte[] performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(cipherText);

    }
}
