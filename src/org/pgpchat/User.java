package org.pgpchat; /** NIS Assignment: User Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * User Class
 */
public class User {

    private String username;
    private X509Certificate certificate;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Constructor
     * @param name username
     * @param certificate
     */
    public User(String name, X509Certificate cert){
        this.username = name;
        this.certificate = cert;
    }

    /**
     * Retrieves username
     * @return username
     */
    public String getName(){
        return username;
    }

    /**
     * Retrieves certificate
     * @return certificate
     */
    public X509Certificate getCertificate(){
        return certificate;
    }

    /**
     * Retrieves public key of user
     * @return
     */
    public PublicKey getUserPublicKey(){
        return certificate.getPublicKey();
    }
}
