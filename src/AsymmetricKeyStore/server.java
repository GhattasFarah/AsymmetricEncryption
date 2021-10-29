package part2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private final String sign = "SHA256withRSA";
    private KeyStore keyStore;


    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port, String pwSv) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());


        byte[] data = new byte[256];
        byte[] signature = new byte[256];
        int numBytes;
        while ((numBytes = in.read(data)) != -1) {

            //reading the bytes and setting up cipher
            in.read(signature);

            //this is to retrieve the server private key
            Key key = keyStore.getKey("server", pwSv.toCharArray());
            PrivateKey serverK = null;
            if (key instanceof PrivateKey){
                serverK = (PrivateKey) key;
            }

            //this is to get the public key for the client
            PublicKey clientKey = keyStore.getCertificate("client").getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverK);

            // decrypt data
            byte[] decryptedBytes = cipher.doFinal(data);
            String msg = new String(decryptedBytes, "UTF-8");
            System.out.println("Server received cleartext "+msg);

            //authenticating message received
            Signature signIn = Signature.getInstance("SHA256withRSA");
            signIn.initVerify(clientKey);
            signIn.update(decryptedBytes);

            //check authentication of the signature
            if(signIn.verify(signature)){
                System.out.println("Valid signature!");
            }else{
                System.out.println("Invalid signature!");
            }

            // encrypt response (this is just the decrypted data re-encrypted)
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clientKey);
            byte[] cipherBytes = cipher.doFinal(decryptedBytes);

            System.out.println("Server sending ciphertext "+new String(Base64.getEncoder().encode(cipherBytes)));

            //signing the bytes with the secret key
            Signature signOut = Signature.getInstance("SHA256withRSA");
            signOut.initSign(serverK);
            signOut.update(decryptedBytes);
            byte[] signedBytes = signOut.sign();

            out.write(cipherBytes);
            out.write(signedBytes);
            out.flush();
        }
        stop();
    }

    /**
     * This is the method to generate the keystore for client and server
     * @throws CertificateException
     * @throws KeyStoreException
     */
    public void keyStore(String path, String pw) throws CertificateException, KeyStoreException {
        KeyStore store = KeyStore.getInstance("JKS");
        try {
            File keystorePath = new File(path);
            store.load(new FileInputStream(keystorePath), pw.toCharArray());
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Error loading keystore. Please try again.");
        }
        keyStore = store;
        System.out.println("Keys stored successfully");
    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args){
        EchoServer server = new EchoServer();
        try {
            server.keyStore(args[0], args[1]);
            server.start(6969, args[2]);
        }catch (NoSuchAlgorithmException e){
        System.out.println("Algorithm can't be found. Please enter again");
        }catch (InvalidKeyException k){
            System.out.println("Key entered is invalid. Please enter valid key");
        }catch (IllegalBlockSizeException b){
            System.out.println("Invalid block size for this cipher.");
        }catch (BadPaddingException b){
            System.out.println("Not sufficient padding for this cipher");
        }catch (IOException i){
            System.out.println("Issue sending message. Please try again");
        }catch (NoSuchPaddingException n){
            System.out.println("Not enough padding. Please try again");
        }catch (SignatureException s){
            System.out.println("Signature isn't a match.");
        }catch (CertificateException e) {
            System.out.println("Invalid certificate. Please try again");
        } catch (KeyStoreException e) {
            System.out.println("Invalid key store instance. Please try again");
        }catch (UnrecoverableKeyException r){
            System.out.println("Unrecoverable key. Please try again");
        }
    }

}



