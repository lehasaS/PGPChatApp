package org.pgpchat; /** NIS Assignment: Message Package Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.io.Serializable;

public class MessagePackage implements Serializable
    {
        private String sender, receiver;
        private byte[] encryptedHash; //hash of the original message encrypted with session key
        private byte[] encryptedMessage; //original message encrypted with session key
        private byte[] encryptedSessionKey; //shared session key encrypted with receiver's public key
        private byte[] initialisationVector; 
        private byte[] protocolMessage; //Protocol message if need - to be interpreted by server

        /**
         * Constructor for object
         * @param sender
         * @param receiver
         * @param hash
         * @param message
         * @param sessionkey
         * @param initvector
         * @param protocolmsg
         */
        public MessagePackage(String sender, String receiver, byte[] hash, byte[] message, byte[] sessionkey, byte[] initvector, byte[] protocolmsg )
            {
                this.sender = sender; 
                this.receiver = receiver;
                encryptedHash = hash;
                encryptedMessage = message;
                encryptedSessionKey = sessionkey;
                initialisationVector = initvector;
                protocolMessage = protocolmsg;
            }

            /**
             * Retrieve package according to index
             * 1 = encrypted Hash
             * 2 = encrypted Message
             * 3 = encrypted Session Key
             * 4 = initialisation vector
             * 5 = protocol message
             * @param index
             * @return
             */
        public byte[] getPackage(int index)
            {
                byte[] empty = null;
                switch (index)
                    {
                        case 1:
                            return encryptedHash; 
                        case 2:
                            return encryptedMessage;
                        case 3:
                            return encryptedSessionKey;
                        case 4:
                            return initialisationVector;
                        case 5:
                            return protocolMessage;
                        default:
                            return empty;
                    }
            }

        /**
         * Retrieves sender
         * @return
         */
        public String getSender(){
            return sender;
        }

        /**
         * Retrieves receiver
         * @return
         */
        public String getReceiver(){
            return receiver;
        }
    }
