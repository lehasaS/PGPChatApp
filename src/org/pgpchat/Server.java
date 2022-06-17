package org.pgpchat; /** NIS Assignment: Server Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;

/**
 * Server class (and Certification Authority)
 */
public class Server {
    static Integer port;
    static int mode;
    static Logger debugger;
    volatile static boolean running;
    static X509CertificateHolder CACertificate;
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    static Vector <ClientHandler> clients = new Vector<>();

    /**
     * Helper function to print all the clients
     */
    public static void printClients(){
        debugger.dbg("We have " + clients.size() + " connections");

        for (ClientHandler client : clients) {
            debugger.dbg("In list: " + client.name);
        }
    }

    /**
     * Helper function to kill all the clients upon sudden termination
     */
    public synchronized static void killClients(){
        for (int i = 0; i < clients.size(); i++) {
            broadcast("$X".getBytes(), "");
            clients.remove(clients.get(i));
        }
        debugger.dbg("The server is exiting.");
    }

    /**
     * Checks if unique new username
     * @param name User name
     * @return true if unique
     */
    synchronized static boolean checkValidUsername(String name){
        for(ClientHandler c : clients){
            if(!(c.getName() == null) && (c.getName().equals(name))){
                return false;
            }
            
        }
        return true;
    }

    /**
     * Writes a message to the output stream
     * 
     * @param msg message
     * @param out writer
     */
    public static void write(byte[] msg, ObjectOutputStream out){
        try{
            out.writeInt(msg.length);
            out.write(msg);
            out.flush();
        }catch(IOException e){
            debugger.dbg("[Couldn't write to output stream!]");
        }
    }

    /***
     * Writes a message package to the output stream
     * @param pckg message package
     * @param out writer
     */
    public static void write(MessagePackage pckg, ObjectOutputStream out){
        try{
            out.writeInt(1);
            out.writeObject(pckg);
            out.flush();
        }catch(IOException e){
            debugger.dbg("[Couldn't write to output stream!]");
        }
    }


    /**
     * Creating the certification authority's certificate
     * MOTIVATION: <a href="https://stackoverflow.com/questions/31618568/how-can-i-create-a-ca-root-certificate-with-bouncy-castle">...</a>
     * <a href="https://vividcode.io/create-self-signed-certificates-using-bouncycastle/">...</a>
     * (with modifications)
     * @return certificate
     */
    private static X509CertificateHolder generateCACertificate(){
        
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair(); //generates public and private keys

            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
            X500Name dName = new X500Name("CN=" + "NIS Assignment CA"); //name of CA
            BigInteger certificateSerialNumber = BigInteger.valueOf(System.currentTimeMillis()); //serial number
            Instant sDate = Instant.now(); //valid from
            Instant eDate = sDate.plus(2 * 365, ChronoUnit.DAYS); //valid for another 2 years
            
            JcaX509v3CertificateBuilder certificateBuilder = //certificate builder
                new JcaX509v3CertificateBuilder(
                    dName, 
                    certificateSerialNumber, 
                    Date.from(sDate), 
                    Date.from(eDate), 
                    dName,
                    publicKey);

            X509CertificateHolder certHolder = certificateBuilder.build(
                new JcaContentSignerBuilder("SHA1withRSA")
                .build(privateKey));

            debugger.dbg("CA Certificate Created!");
            return certHolder;
        } catch(Exception e){
            debugger.dbg("[CA Certification Error!]");
        }
        
        return null;
    }

    /**
     * CA-generated user certificate
     * @param username User name
     * @param key Public Key
     * @return user certificate
     */
    static X509Certificate generateUserCertificate(String username, PublicKey key){
        try{ 

            //MOTIVATION: https://vividcode.io/create-self-signed-certificates-using-bouncycastle/ 
            //https://stackoverflow.com/questions/31618568/how-can-i-create-a-ca-root-certificate-with-bouncy-castle 
            //(with modifications)
            X500Name CAName = CACertificate.getIssuer(); //CA name; distinguished name
            X500Name userName = new X500Name("CN=" + username); //User's name; common/subject name
            BigInteger certificateSerialNumber = BigInteger.valueOf(System.currentTimeMillis()); //serial number
            String sigAlgorithm = "SHA256WithRSA"; //signature algorithm
            ContentSigner contentSigner = 
                new JcaContentSignerBuilder(sigAlgorithm)
                    .build(privateKey); //content signer
            SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(key.getEncoded()); //changed from publicKey
            Instant sDate = Instant.now(); //valid from
            Instant eDate = sDate.plus(2 * 365, ChronoUnit.DAYS); //valid for another 2 years
            X509v3CertificateBuilder certificateBuilder = //certificate builder
                new X509v3CertificateBuilder(
                    CAName, 
                    certificateSerialNumber, 
                    Date.from(sDate), 
                    Date.from(eDate), 
                    userName,
                    pubKeyInfo);
            X509Certificate certificate = //certificate!
                new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certificateBuilder.build(contentSigner));
            debugger.dbg("Client Certificate Created!");
            return certificate;
        }catch(Exception e){
            debugger.dbg("[Client Certificate Error!]");
            System.out.println(e);
        }
        return null;
    }

    /**
     * Sends a message to all clients
     * @param message Message
     * @param sender Sender
     */
    public synchronized static void broadcast(byte[] message, String sender){
        Logger debugger = new Logger(mode);
        debugger.dbg("Broadcasting to clients");

        // iterate through handlers
        for (ClientHandler client : clients) {
            // send to all clients except the sender (except for exit messages)
            if (!client.getName().equals(sender) || Format.getControl(message) == Format.EXIT) {
                write(message, client.getOutputStream());
            }
        }
    }

    /***
     * Broadcasts message package
     * @param pckg Message Package
     */
    public synchronized static void broadcastMessagePackage(MessagePackage pckg){
            Logger debugger = new Logger(mode);
            debugger.dbg("Broadcasting message package to clients");

        for (ClientHandler client : clients) {
            // send to all clients except the sender (except for exit messages)
            if (client.getName().equals(pckg.getReceiver())) {
                write(pckg, client.getOutputStream());
            }
        }
    }

    /**
     * Broadcasts the existing clients to new client
     * @param rClient the receiving user
     * @param certificate the new client's certificate
     * 
     */
    public static void sendClients(String rClient, X509Certificate certificate){
        //1: send new user's certificate to all clients
        try{

            byte[] certArr = Format.encodeClient(certificate);   

            for(int i = 0; i < clients.size(); i++ ){ // also send to receiving client
            
                ClientHandler current = clients.get(i); // current client to be sent 
                debugger.dbg("Sending client " + rClient + " to " + current.getName());
                write(certArr, current.getOutputStream()); //send

                if(current.getName().equals(rClient)){
                    sendCAPublicKey(current); //send the new user the CA's public key

                    //2: send new user the pre-existing clients

                    // current client to be sent
                    for (ClientHandler current2 : clients) {
                        if (!current2.getName().equals(rClient)) {
                            debugger.dbg("Sending client " + current2.getName() + " to " + rClient);
                            byte[] certArr2 = null;
                            try {
                                certArr2 = Format.encodeClient(current2.getCertificate());
                            } catch (CertificateEncodingException e) {
                                debugger.dbg("[Certificate Encoding Exception!]");
                            }
                            write(Objects.requireNonNull(certArr2), current.getOutputStream()); //send
                        }
                    }
                }
            }
        }catch(Exception e){
            debugger.dbg("[Failed to send to clients!]");
        }    
    }

    /**
     * Send the Certification Authority's public key
     * @param rClient Client Handler
     */
    private static void sendCAPublicKey(ClientHandler rClient){
        debugger.dbg("Sending " + rClient.getName() + " the CA's Public Key");
        write(Format.encodeCAPublicKey(publicKey), rClient.getOutputStream());
    }

    /**
     * Iterates through the ClientHandlers to remove associated clients
     * @param user User
     * @param out writer
     */
    public synchronized static void removeClient(String user, ObjectOutputStream out) {
        for (int i = 0; i < clients.size(); i++) {
            if ((clients.get(i).name.equals(user)) && (clients.get(i).getOutputStream().equals(out))) {
                clients.remove(clients.get(i));
            }
        }
    }

    /**
     * Driver function for the Server
     * 
     * @param args Arguments
     */
    public static void main(String[] args) {
        // set status
        running = true;

        // check arguments
        if (args.length < 2) {
            System.out.println("Usage: <port> <debug mode>");
            return;
        }

        // set arguments
        port = Integer.parseInt(args[0]);
        mode = Integer.parseInt(args[1]);
        
        // instantiate debugger
        debugger = new Logger (mode);

        // handles a sudden kill signal
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                killClients();
            }
        });

        ServerSocket serverSocket = null;
        
        debugger.dbg("Initialising server...");

        try{// server is listening on a given port
            serverSocket = new ServerSocket(port);
            serverSocket.setReuseAddress(true);
            
            //Create CA
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            CACertificate = generateCACertificate();
            debugger.dbg("Socket created successfully. Clients may now join.");

            // running infinite loop for getting client requests
            while (running){

                // socket object to receive incoming client
                Socket client = serverSocket.accept();
                
                // create a new thread object
                ClientHandler clientSocket = new ClientHandler(client, mode);

                // create client thread
                Thread t = new Thread(clientSocket);

                // add new client connection
                clients.add(clientSocket);

                // start thread
                t.start();
            }
        }catch (IOException e) {
            e.printStackTrace();
        } 
    } 
}

    /**
     * ClientHandler thread 
     */
class ClientHandler implements Runnable {
    Socket socket;
    ObjectInputStream in;
    ObjectOutputStream out;
    public String name;
    private int mode;
    private X509Certificate certificate;
    public PublicKey publicKey;

    /**
     * ClientHandler constructor
     * @param socket Socket
     * @param mode Mode
     */
    public ClientHandler(Socket socket, int mode)
    {
        this.socket = socket;
        this.mode = mode;
    }

    /**
     * Adds a client to the linked list of clients
     * @param temp name
     */
    void addClientName(String temp) {
        name = temp;
    }

    /**
     * Gets the output stream of a client
     * @return output stream
     */
    ObjectOutputStream getOutputStream(){
        return out;
    }

    /**
     * Retrieve username
     * @return name
     */
    String getName(){
        return name;
    }

    /**
     * Retrieves client's certificate
     * @return certificate
     */
    X509Certificate getCertificate(){
        return certificate;
    }

    /**
     * Retrieve public key
     * @return public key
     */
    PublicKey getPublicKey(){
        return publicKey;
    }

    /**
     * Runs the main thread
     */
    public void run(){
        String temp;
        Logger debugger = new Logger(mode);
        boolean running = true;
        byte[] line = null;
        int inputLength;

        try {
        
            // get the output stream of client
            out = new ObjectOutputStream(socket.getOutputStream());

            // get the input stream of client
            in = new ObjectInputStream(socket.getInputStream());

            // loop to receive input from client
            while(running){
                inputLength = in.readInt(); // length of message
                MessagePackage pckg = null;
                if(inputLength == 1){
                    Object input = in.readObject();
                    if(input instanceof MessagePackage){
                        pckg = (MessagePackage) input;
                        debugger.dbg("Received message package.");
                        
                    }
                    else
                    {
                        debugger.dbg("[Couldn't read in line!]");
                    }                       
                }
                else{
                    line = new byte[inputLength];
                    in.readFully(line, 0, inputLength); // read the message
                }

                

                if (pckg != null){
                        debugger.dbg("Message Package received.");
                        Server.broadcastMessagePackage(pckg);
                }
                    
                else{
                    if (line != null) {
                        debugger.dbg("Received a message.");
    
                        // interpret message from client
                        if (Format.isControl(line)) {
                            temp = Format.getStringContents(line);
    
                            // act according to control code
                            switch (Format.getControl(line)) {

                                // new client has joined
                                case Format.JOIN -> {
                                    byte[] tempByteName = new byte[line[2]];
                                    System.arraycopy(line, 3, tempByteName, 0, line[2]);
                                    String tempStringName = new String(tempByteName, StandardCharsets.UTF_8);
                                    byte[] tempByteKey = Arrays.copyOfRange(line, line[2] + 3, line.length);
                                    X509EncodedKeySpec spec = new X509EncodedKeySpec(tempByteKey);
                                    PublicKey tempKey = null;
                                    try {
                                        tempKey = KeyFactory.getInstance("RSA").generatePublic(spec);
                                    } catch (InvalidKeySpecException e) {
                                        debugger.dbg("[Invalid KeySpec Exception!]");
                                        System.out.println(e);
                                    } catch (NoSuchAlgorithmException e) {
                                        debugger.dbg("[No Such Algorithm Exception!]");
                                    }
                                    if (name == null) {

                                        if (Server.checkValidUsername(tempStringName)) {
                                            addClientName(tempStringName);
                                            debugger.print(tempStringName + " joined the chat.");
                                            certificate = Server.generateUserCertificate(tempStringName, tempKey);
                                            Server.sendClients(tempStringName, certificate);
                                        } else {
                                            debugger.print("Non-unique username received!");
                                            addClientName(tempStringName);
                                            Server.write(Format.encodeRejection(tempStringName), out);
                                            Server.removeClient(tempStringName, out);
                                            running = false;
                                        }

                                    }
                                }

                                // a client has left
                                case Format.EXIT -> {
                                    debugger.print(temp + " left the chat.");
                                    Server.broadcast(line, temp);
                                    Server.removeClient(temp, out);
                                    running = false;
                                }
                                default -> {
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                }
                if (in != null) {
                    in.close();
                    socket.close();
                }
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}