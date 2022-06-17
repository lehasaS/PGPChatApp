package org.pgpchat; /** NIS Assignment: Client Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.swing.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;

/**
 * Client class
 */
class Client extends JFrame implements ActionListener{

    public static Logger debugger;
    static volatile AtomicBoolean clientRunning, serverExit;
    private static Vector <User> clients = new Vector<>();
    private static PublicKey CAKey = null;
    private static X509Certificate certificate;
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static SecretKey sessionKey;
    int port;
    String hostname;
    int mode; //0 = no debug; 1 = debug
    String username = null;
    Socket socket = null;
    ReceiveThread receive = null;
    SendThread send = null;
    Thread rThread = null;
    Thread sThread = null;
    volatile AtomicBoolean usernameEmpty, clientSuccessful;

    
    //GUI variables
    private JPanel northPanel; //displays the chat name and quit button
    private JPanel subNorthPanel1; //displays name
    private JPanel subNorthPanel2; //displays name
    private JPanel subNorthPanel3; //displays quit button
    private JPanel chatPanel; //displays the group chat
    private JPanel loginPanel; //dispplays the welcome page to submit username
    private JPanel southPanel; //displays the message typing field
    private JPanel westPanel; //border
    private JPanel eastPanel; //border
    private JLabel nameLabel; //group chat name
    private JLabel creditLabel; //credit
    private JLabel loginLabel; //login instruction
    private JButton loginButton; //for login page
    private JButton sendButton; //send message in chat
    private JButton leaveButton; //leave chat and quit application
    private JTextField messageField; //where the user will send messages
    private JTextField usernameField; //where the user submits their username
    private JScrollPane scrollPane; //to allow scrolling
    private JTextArea groupChatArea; //to display all messages
    private String messages; //the messages sent
    private static final int WIDTH = 1000;
    private static final int HEIGHT = 600;
    private static final Color LIGHTGREEN = new Color(0, 200, 0);
    private static final Color DARKGREEN = new Color(0, 100, 0);
    private static final Font LARGEFONT = new Font("Tahoma", Font.BOLD, 20);
    private static final Font SMALLFONT = new Font("Tahoma", Font.BOLD, 16);    

    /**
     * Constructor (for GUI)
     * @param port number
     * @param hostname
     * @param mode (0 for no debugging statements, 1 for debugging statements)
     */
    public Client(int port, String hostname, int mode){

        //Frame
        super("CSC4026Z NIS Assignment (by GRNCLA009, IMRJAN001, RYXJOS002, SXXLEH001)");
        setSize(WIDTH, HEIGHT); //not fullscreen
        setBackground(LIGHTGREEN);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE); //rather use quit button so it can call the disconnect messages
        setLayout(new BorderLayout());  

        //Panels

        //North
        northPanel = new JPanel();
        northPanel.setLayout(new GridLayout(0, 3));
        add(northPanel, BorderLayout.NORTH);

        //SubNorthPanels 
        subNorthPanel1 = new JPanel();
        subNorthPanel1.setBackground(DARKGREEN);
        northPanel.add(subNorthPanel1);
        
        subNorthPanel2 = new JPanel();
        subNorthPanel2.setBackground(DARKGREEN);
        subNorthPanel2.setLayout(new FlowLayout(FlowLayout.CENTER));
        northPanel.add(subNorthPanel2);

        subNorthPanel3 = new JPanel();
        subNorthPanel3.setBackground(DARKGREEN);
        subNorthPanel3.setLayout(new FlowLayout(FlowLayout.RIGHT));
        northPanel.add(subNorthPanel3);


        //Chat
        chatPanel = new JPanel();
        chatPanel.setBorder(BorderFactory.createStrokeBorder(new BasicStroke(3.5f))); //black border

        //Login
        loginPanel = new JPanel();
        loginPanel.setBackground(LIGHTGREEN);
        loginPanel.setLayout(new GridBagLayout());
        setLocationRelativeTo(null);
        add(loginPanel, BorderLayout.CENTER);

        //Bottom
        southPanel = new JPanel();
        add(southPanel, BorderLayout.SOUTH);
        southPanel.setBackground(DARKGREEN);

        //West
        westPanel = new JPanel();
        westPanel.setBackground(DARKGREEN);
        add(westPanel, BorderLayout.WEST);

        //East
        eastPanel = new JPanel();
        eastPanel.setBackground(DARKGREEN);
        add(eastPanel, BorderLayout.EAST);

        //Buttons

        //Login
        loginButton = new JButton("  ENTER  ");
        loginButton.setForeground(Color.WHITE);
        loginButton.setBackground(DARKGREEN);
        loginButton.addActionListener(this);

        //Send message
        sendButton = new JButton("  SEND  ");
        sendButton.setForeground(Color.WHITE);
        sendButton.setBackground(LIGHTGREEN);
        sendButton.addActionListener(this);

        //Quit
        leaveButton = new JButton("  LEAVE  ");
        leaveButton.setForeground(Color.WHITE);
        leaveButton.setBackground(Color.RED);
        leaveButton.addActionListener(this);

        //Labels

        //Login Instruction
        loginLabel = new JLabel("Welcome! Please enter your username: ");
        loginLabel.setForeground(Color.BLACK);
        loginLabel.setFont(SMALLFONT);
        loginPanel.add(loginLabel);
        
        //Credit        
        creditLabel = new JLabel("CREATED BY CLAUDIA GREENBERG, JANE IMRIE, JOSIE REY & LEHASA SEOE");
        creditLabel.setForeground(Color.BLACK);
        creditLabel.setFont(SMALLFONT);
        southPanel.add(creditLabel);

        //Title
        nameLabel = new JLabel("GROUP CHAT");
        nameLabel.setForeground(Color.BLACK);
        nameLabel.setFont(LARGEFONT);
        subNorthPanel1.add(new JLabel());
        subNorthPanel2.add(nameLabel);

        //JTextFields

        //Message 
        messageField = new JTextField(80);

        //Username
        usernameField = new JTextField(20);
        loginPanel.add(new JLabel("         "));
        loginPanel.add(usernameField);
        loginPanel.add(new JLabel("         "));
        loginPanel.add(loginButton);

        //TextArea
        groupChatArea = new JTextArea(messages);
        groupChatArea.setEditable(false);

        //ScrollPane        
        chatPanel.setLayout(new BoxLayout(chatPanel, BoxLayout.PAGE_AXIS));
        scrollPane = new JScrollPane(groupChatArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        chatPanel.add(scrollPane);

        // set atomic booleans
        clientRunning = new AtomicBoolean(true);
        serverExit = new AtomicBoolean(false);
        
        // instantiate debugger
        debugger = new Logger(mode);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try{
            KeyPair keyPair = AsymmetricEncryptionUtility.generateRSAKeys();
            sessionKey = SymmetricEncryptionUtility.createAESKey();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate(); 
            debugger.dbg("Public Key for "+ username + ":" + new String(Hex.encode(publicKey.getEncoded())));
            debugger.dbg("Private Key for "+ username + ":" +new String(Hex.encode(privateKey.getEncoded())));
        }catch(Exception e){
            debugger.dbg("Cannot create keys!");
        }

        try {

            // establish a connection by providing hostname and port

            SocketFactory basicSocketFactory = SocketFactory.getDefault();
            socket = basicSocketFactory.createSocket(hostname, port);
            
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

            // handles a sudden kill signal
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    if (out != null) {
                        try{
                            byte[] sender = Format.encodeExit(username);
                            out.writeInt(sender.length);
                            out.write(sender);
                            clientRunning.set(false);
                        }catch(Exception e){
                            debugger.dbg("");
                        }
                    }
                }
            });

            //GUI
            setVisible(true);

            usernameEmpty = new AtomicBoolean(true);

            // create sending thread
            send = new SendThread(out, publicKey, privateKey);
            sThread = new Thread(send);
            sThread.start();

            // create receiving thread
            receive = new ReceiveThread(in, publicKey, privateKey);
            rThread = new Thread(receive);
            rThread.start();

            // wait for signal to terminate program
            while (clientRunning.get()) {
                // in the event of a server exit, we assume that the send thread will not close
                // alone, so we terminate it
                if (serverExit.get()) {
                    debugger.dbg("Server exited.");
                    messages = debugger.log(groupChatArea, messages, "Server exited. Chat is no longer running.");
                    messageField.setEditable(false);
                    clientRunning.set(false);
                    sThread.interrupt();
                }
            }

            if(!sThread.isInterrupted()){sThread.interrupt();}
            // close resources
            out.close();
            in.close();
            socket.close();

        } catch (IOException e) {
            debugger.dbg("IO Error.");
            e.printStackTrace();
        }
    }

    /**
     * Reads in byte array
     * @param message Message
     * @param in stream
     */
    static void read(byte[] message, ObjectInputStream in){
        try{
            int inputLength = in.readInt(); // read length of incoming message
        
            if(inputLength > 0) {
                message = new byte[inputLength];
                in.readFully(message, 0, message.length); // read the message
            }
        }catch(IOException e){
            debugger.dbg("[Unable to read message!]");
        }
    }

    /**
     * Sets username
     * @param u username
     */
    synchronized void setUsername(String u){
        username = u;
        usernameEmpty.set(false);
    }

    /**
     * ActionListener
     */
    public synchronized void actionPerformed(ActionEvent e) {
        String button = e.getActionCommand();

        switch(button){
            case "  ENTER  ":
                setUsername(usernameField.getText().trim());
                break;

            case "  SEND  ":
                send.setLine(messageField.getText());
                break;

            case "  LEAVE  ":
                send.write(Format.encodeExit(username));
                send.running.set(false);
                receive.running.set(false);
                sThread.interrupt();
                System.exit(0);
                break;

        }
    }

    /**
     * Main function for the client
     * @param args
     */
    public static void main(String[] args) throws Exception{
        
        // check arguments
        if (args.length != 3) {
            System.out.println("Usage: <port>, <hostname>, <debug mode>");
            return;
        }

        Client c = new Client(Integer.parseInt(args[0]), args[1], Integer.parseInt(args[2]));
        c.setVisible(true);
    }

    /**
     * Thread to handle receipt of messages from the server and other clients
     */
    private class ReceiveThread implements Runnable {
        ObjectInputStream in;
        volatile AtomicBoolean running;
        private PublicKey publicKey;
        private PrivateKey privateKey;


        /**
         * Constructor for the receiving thread
         * 
         * @param inStream
         * @param publicKey public key
         * @param privateKey private key
         */
        public ReceiveThread(ObjectInputStream inStream, PublicKey publicKey, PrivateKey privateKey) {
            this.in = inStream;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            running = new AtomicBoolean(true);
        }

        /**
         * Runs the receiving thread
         */
        public void run() {
            String temp, user, msg;
            byte[] line = null;
            int inputLength;

            while(usernameEmpty.get()){} //waiting for username to be added
            
            try {
                // loop to receive input from client
                while (running.get()) {
                    if(!socket.isClosed()){
                        inputLength = in.readInt(); // read length of incoming message
                        MessagePackage pckg = null;
                        if(inputLength == 1) {
                            Object input = in.readObject();
                            if (input instanceof MessagePackage)
                                {
                                    pckg = (MessagePackage) input;
                                    debugger.dbg("Received message package from Server");
                                    
                                }
                            
                            else
                            {
                                debugger.dbg("[Couldn't read in line!]");
                            }
                        
                        }
                        else
                        {
                            line = new byte[inputLength];
                            in.readFully(line, 0, inputLength); // read the message
                        }
                        

                        if (pckg != null)
                            {
                            
                                byte[][] payload = new byte[4][0];
                                payload[0] = pckg.getPackage(1);
                                payload[1]= pckg.getPackage(2);
                                payload[2] = pckg.getPackage(3);
                                payload[3] = pckg.getPackage(4);

                                // Get Session key
                                SecretKey currentSessionKey = MessageDecrypt.getSessionKey(payload, privateKey);
                                // Use session key to get message
                                String message = MessageDecrypt.getMessage(payload, currentSessionKey).trim();
                                
                                byte[] encryptedHash = MessageDecrypt.getSignature(payload, currentSessionKey);
                                byte[] newHash = HashUtility.createSHA2Hash(message);
                                
                                debugger.dbg("Message: ["+message+"]");
                                debugger.dbg("New Hash: " + new String(Hex.encode(newHash)));
                                debugger.dbg("Encrypted Hash: " + new String(Hex.encode(encryptedHash)));

                                byte[] decryptedHash = null;
                                        
                                //decryptedHash = AsymmetricEncryptionUtility.performRSADecryption(encryptedHash, userPublicKey) ;
                                debugger.dbg("Message sent from : " + pckg.getSender());
                                for(User client : clients){
                                    if(client.getName().equals(pckg.getSender())){
                                        debugger.dbg("Using key from ___ to authenticate hash : " + client.getName());
                                        debugger.dbg("Public Key found for decryption: "+  new String(Hex.encode(client.getUserPublicKey().getEncoded())));
                                        decryptedHash = AsymmetricEncryptionUtility.performRSADecryption(encryptedHash, client.getUserPublicKey());
                                    }
                                }
                                if(HashUtility.compareHash(newHash, decryptedHash)){
                                    debugger.dbg("Message Integrity Authenticated");
                                    messages = debugger.prompt(groupChatArea, messages, pckg.getSender(), message);
                                }
                                else{
                                    String errorMessage = "The message sent by "+pckg.getSender()+" has been tampered with and will not be displayed";
                                    messages = debugger.prompt(groupChatArea, messages, "SERVER:", errorMessage);
                                } 
                                revalidate();
                                repaint();
                            }
                        else if (!(line == null)) {
                            
                            debugger.dbg("Received protocol message");


                            // interpret message from client
                            if ((Format.isControl(line))) {
                                String message = new String(line);
                                temp = message; //Format.getContents(); //what has been received without the preceding symbol
                                
                                // act according to control code
                                switch (Format.getControl(line)) {


                                    // new client has joined
                                    case Format.JOIN:
                                        messages = debugger.log(groupChatArea, messages, temp + " joined the chat");
                                        revalidate();
                                        repaint();
                                        break;

                                    // a client has left
                                    case Format.EXIT:
                                        //temp is a String with just the name
                                        String leavingUser = Format.getStringContents(line);
                                        if (leavingUser.equals(username)) {
                                            clientRunning.set(false);
                                            return;
                                        }
                                    
                                        else{
                                            //remove from client list
                                            synchronized(clients){
                                                User tempUser = null;
                                                for(User u : clients){
                                                    if(u.getName().equals(leavingUser)){
                                                        tempUser = u;
                                                    }
                                                }
                                                clients.remove(tempUser);
                                            }
                                                                                    
                                        }

                                        messages = debugger.log(groupChatArea, messages, leavingUser + " left the chat");
                                        revalidate();
                                        repaint();
                                        break;

                                    case Format.SERVER_EXIT:
                                        // handles a server exit message
                                        debugger.dbg("(sudden server exit)");

                                        Client.serverExit.set(true); //come back to check this
                                        return;

                                    case Format.FROM:
                                        // scrapes information from the message content
                                        temp = Format.getStringContents(line);
                                        user = Format.getUser(temp);
                                        msg = Format.getMsgBody(temp);
                                        messages = debugger.prompt(groupChatArea, messages, user, msg);
                                        break;

                                    case Format.CLIENT_LIST: //receive all pre-existing clients
                                        // decode certificate
                                        InputStream tempInputStream = new ByteArrayInputStream(Format.getByteContents(line));
                                        X509Certificate tempCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(tempInputStream);
                                        
                                        // extract username
                                        X500Name tempX500Name = new JcaX509CertificateHolder(tempCert).getSubject();
                                        String tempName = tempX500Name.toString().substring(3);

                                        if(!tempName.equals(username)){
                                            messages = debugger.log(groupChatArea, messages, tempName + " joined the chat");
                                            revalidate();
                                            repaint();
                                        }
                                        else{
                                            debugger.dbg("Certificate received");
                                            messages = debugger.log(groupChatArea, messages, "You have successfully joined the chat!");
                                            clientSuccessful = new AtomicBoolean(true);
                                            revalidate();
                                            repaint();
                                            Client.certificate = tempCert;
                                        }
                                        synchronized(clients){
                                            Client.clients.add(new User(tempName, tempCert));
                                        }
                                        break;
                                    
                                    case Format.CA_KEY:
                                        
                                        byte[] contents = Format.getByteContents(line);
                                        X509EncodedKeySpec spec = new X509EncodedKeySpec(contents);
                                        
                                        try{
                                            CAKey = KeyFactory.getInstance("RSA").generatePublic(spec);
                                            debugger.dbg("CA Public Key Received\n");
                                        }catch(InvalidKeySpecException e){
                                            debugger.dbg("[Invalid KeySpec Exception!]");
                                            System.out.println(e);
                                        }catch(NoSuchAlgorithmException e){
                                            debugger.dbg("[No Such Algorithm Exception!]");
                                        }

                                        break;
                                    
                                    case Format.REJECT:
                                        
                                        System.out.println("Username taken. Please reconnect with a new username.");
                                        clientSuccessful = new AtomicBoolean(false);
                                        clientRunning.set(false);
                                        running.set(false);
                                        System.exit(0);
                                    default:
                                        break;
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Thread to handle sending of input
     */
    private class SendThread implements Runnable {
        private ObjectOutputStream out;
        private volatile AtomicBoolean running, lineEmpty;
        private PublicKey publicKey;
        private PrivateKey privateKey;
        String line = null;

        /**
         * Constructor for the SendThread
         * 
         * @param outStream
         */
        public SendThread(ObjectOutputStream outStream, PublicKey publicKey, PrivateKey privateKey) {
            this.out = outStream;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            
            running = new AtomicBoolean(true);
            lineEmpty = new AtomicBoolean(true);
        }

        synchronized void setLine(String msg){
            this.line = msg;
            lineEmpty.set(false);
        }

        /**
         * Writes a message to the output stream
         * 
         * @param msg
         */
        public void write(byte[] msg) {
            try{                
                if(!serverExit.get()){
                    debugger.dbg("Sending protocol message to server");
                    out.writeInt(msg.length);
                    out.write(msg);
                    out.flush();
                }                
            }catch(IOException e){
                debugger.dbg("[Couldn't write to output stream!]");
            }
        }

        /**
         * Write message package
         * @param pckge
         * @throws IOException
         */
        public void write(MessagePackage pckge) throws IOException{
            debugger.dbg("Sending message package to server");
            out.writeInt(1);
            out.writeObject(pckge);
        }


        /**
         * Runs the thread
         */
        public void run() {
            while(usernameEmpty.get()){} //wait until they have entered the chat
            
            // notify server of joining
            write(Format.encodeJoin(username, publicKey));



            while(clientSuccessful == null){} //waiting for client to be accepted or rejected

            if(clientSuccessful.get()){

                //update GUI
                southPanel.removeAll(); ;
                southPanel.add(messageField);
                southPanel.add(sendButton);
                remove(loginPanel);
                add(chatPanel, BorderLayout.CENTER);
                subNorthPanel3.add(leaveButton);
                revalidate();
                repaint();

                // obtain user input
                try {
                    // receive loop
                    while (running.get()) {
                        while(lineEmpty.get()){} //wait for line

                        // process user input
                        // encodes the message from user input
                        byte[] protocolMessage = Format.encodeMsg(username);
                        
                        // sending message to each client
                        // retrieving each user's public keys
                        for (User client : clients) {
                            if (!client.getName().equals(username)) { // check that it's not the current client
                                debugger.dbg("Retrieving public key for user: " + client.getName());
                                
                                PublicKey receiverPublicKey = client.getUserPublicKey();
                                byte[] initializationVector = SymmetricEncryptionUtility.createInitializationVector();//This will be sent to everyone
                                byte[][] payloadSent = MessageEncrypt.sentPayload(line.trim(), sessionKey, initializationVector, receiverPublicKey, this.privateKey, protocolMessage);
                                // send to the server
                                MessagePackage pckge = new MessagePackage(username, client.getName(), payloadSent[0], payloadSent[1], payloadSent[2], payloadSent[3], payloadSent[4]);
                                write(pckge);
                            }

                        }
                        if(!line.equals("")){
                            messages = debugger.prompt(groupChatArea, messages, "You", line);
                        }
                        setLine(null);
                        messageField.setText("");
                        lineEmpty.set(true);
                    }
                } catch (IOException e) {
                    debugger.dbg("IO ERROR");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}