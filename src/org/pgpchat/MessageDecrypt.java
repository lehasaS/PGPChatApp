package org.pgpchat; /** NIS Assignment: Decryption Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MessageDecrypt {

    /**
     * Retrieves session key
     * @param encryptedPayload payload
     * @param privateKey private key
     * @return session (secret) key
     * @throws Exception exception
     */
    public static SecretKey getSessionKey(byte[][] encryptedPayload, PrivateKey privateKey) throws Exception{
        if (encryptedPayload.length != 4) throw new AssertionError();
        byte[] decodedSessionKey = encryptedPayload[2];
        byte[] encodedKey = AsymmetricEncryptionUtility.performRSAKeyDecryption(decodedSessionKey, privateKey);
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES/CBC/PKCS5Padding");
    }

    /**
     * Retrieves signature
     * @param encryptedPayload payload
     * @param sessionKey session key
     * @return signature
     * @throws Exception exception
     */
    public static byte[] getSignature(byte[][] encryptedPayload, SecretKey sessionKey) throws Exception{
        if (encryptedPayload.length != 4) throw new AssertionError();
        byte[] decodedCompressedSignature = encryptedPayload[0];
        byte[] initializationVector = encryptedPayload[3];

        byte[] decryptedSignature = SymmetricEncryptionUtility.performAESDecryption(decodedCompressedSignature, sessionKey, initializationVector);
        byte[] output = Compressor.decompress(decryptedSignature);
        return output;
    }

    /**
     * Retrieves message
     * @param encryptedPayload payload
     * @param sessionKey session key
     * @return message
     * @throws Exception Exception
     */
    public static String getMessage(byte[][] encryptedPayload, SecretKey sessionKey) throws Exception{
        if (encryptedPayload.length != 4) throw new AssertionError();
        byte[] decodedCompressedMessage = encryptedPayload[1];
        byte[] initializationVector = encryptedPayload[3];

        byte[] decryptedMessage = SymmetricEncryptionUtility.performAESDecryption(decodedCompressedMessage, sessionKey, initializationVector);
        return new String (Compressor.decompress(decryptedMessage));
    }
}
