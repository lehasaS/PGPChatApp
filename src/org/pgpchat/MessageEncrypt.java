package org.pgpchat; /** NIS Assignment: Encryption Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class MessageEncrypt { 

    /**
     * Create client signature
     * @param message Message
     * @param clientPrivateKey Private Key
     * @return client signature
     * @throws Exception Exception
     */
    public static byte[] makeClientSignature(String message, PrivateKey clientPrivateKey) throws Exception{
        
        byte[] hashedMessage = HashUtility.createSHA2Hash(message.trim());
        byte[] output = AsymmetricEncryptionUtility.performRSAEncryption(hashedMessage, clientPrivateKey);
        return output;
    }


    /**
     * Encrypt client message
     * @param message Message
     * @param key Shared Key
     * @param initializationVector Initialization Vector
     * @return encrypted message
     * @throws Exception Exception
     */
    public static byte[] encryptClientMessage(byte[] message, SecretKey key, byte[] initializationVector) throws Exception{
        return SymmetricEncryptionUtility.performAESEncryption(message, key, initializationVector);
    }

    /**
     * Adds Signature and Cipher to sent payload
     * @param message Message
     * @param sessionKey Session Key
     * @param initializationVector Initialization Vector
     * @param clientPrivateKey Private Key
     * @return byte array of sent payload
     * @throws Exception Exception
     */
    public static byte[][] signatureCipherCompression(String message, SecretKey sessionKey, byte[] initializationVector, PrivateKey clientPrivateKey) throws Exception{
        byte[] signedHash = makeClientSignature(message, clientPrivateKey);
        
        byte[] compressedMessage = Compressor.compress(message.getBytes());
        byte[] compressedSignedHash = Compressor.compress(signedHash); //Compressor.compress(signedHash);
        //System.out.println("Hash that is given: "+ new String(Hex.encode((compressedSignedHash))));
        //System.out.println("Message: " + message);
        byte[] encryptedMessage = encryptClientMessage(compressedMessage, sessionKey, initializationVector);
        byte[] encryptedHash = encryptClientMessage(compressedSignedHash, sessionKey, initializationVector);


        byte[][] cipherTextHashPayload = new byte[5][0];
        
        cipherTextHashPayload[0] = encryptedHash;
        cipherTextHashPayload[1] = encryptedMessage ;
        return cipherTextHashPayload;
    }

    /**
     * Prepares sent payload
     * @param message Message
     * @param sessionKey Session Key
     * @param initializationVector Initialization Vector
     * @param receiveKey Receiver Public Key
     * @param clientPrivateKey Sender Private Key
     * @param protocolMessage Protocol Message
     * @return byte array of sent payload
     * @throws Exception Exception
     */
    public static byte[][] sentPayload(String message, SecretKey sessionKey, byte[] initializationVector, PublicKey receiveKey, PrivateKey clientPrivateKey, byte[] protocolMessage) throws Exception{
        byte[][] encryptedPayload = signatureCipherCompression(message, sessionKey, initializationVector, clientPrivateKey);
        encryptedPayload[2] = AsymmetricEncryptionUtility.performRSAKeyEncryption(sessionKey, receiveKey);
        encryptedPayload[3] = initializationVector;
        encryptedPayload[4] = protocolMessage;
        return encryptedPayload;
    }
}
