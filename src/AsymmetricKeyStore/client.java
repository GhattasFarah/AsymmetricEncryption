package part2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoClient {
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyStore keyStore;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Sends message to server and receives a reply
     * @param msg
     * @param pwCl
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    public String sendMessage(String msg, String pwCl) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableKeyException {
        System.out.println("Client sending cleartext "+msg);
        byte[] data = msg.getBytes("UTF-8");

        //this is to retrieve the client private key
        Key key = keyStore.getKey("client", pwCl.toCharArray());
        PrivateKey clientK = null;
        if (key instanceof PrivateKey){
            clientK = (PrivateKey) key;
        }

        //this is to get the public key for the client
        PublicKey serverK = keyStore.getCertificate("server").getPublicKey();

        //setting up the cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverK);
        byte[] cipherBytes = cipher.doFinal(data);

        //signing the bytes with the secret key
        Signature signOut = Signature.getInstance("SHA256withRSA");
        signOut.initSign(clientK);
        signOut.update(data);
        byte[] signedBytes = signOut.sign();

        // encrypt data
        System.out.println("Client sending ciphertext "+ new String(Base64.getEncoder().encode(cipherBytes)));
        out.write(cipherBytes);
        out.write(signedBytes);
        out.flush();

        //decrypting reply
        byte[] received = new byte[256];
        byte[] receivedSigned = new byte[256];
        in.read(received);
        in.read(receivedSigned);

        //setting up cipher to decrypt
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientK);
        byte[] decryptedBytes = cipher.doFinal(received);
        String reply = new String(decryptedBytes, "UTF-8");
        System.out.println("Server returned cleartext "+reply);

        //authenticating using servers public key
        Signature signIn = Signature.getInstance("SHA256withRSA");
        signIn.initVerify(serverK);
        signIn.update(decryptedBytes);

        //check the authentication of the signature
        if(signIn.verify(receivedSigned)){
            System.out.println("Valid signature!");
        }else{
            System.out.println("Invalid signature!");
            throw new SignatureException("Invalid signature!");
        }
        return reply;
    }

    /**
     * This is the method to generate the keystore for client and server
     * @throws CertificateException
     */
    public void keyStore(String path, String pw) throws CertificateException, KeyStoreException {
        KeyStore store = KeyStore.getInstance("JKS");
        try {
            File keystoreLoc = new File(path);
            store.load(new FileInputStream(keystoreLoc), pw.toCharArray());
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Error loading keystore. Please try again.");
        }
        keyStore = store;
        System.out.println("Keys stored successfully.");
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) {
        EchoClient client = new EchoClient();
        try {
            client.keyStore(args[0],args[1]);
            client.startConnection("127.0.0.1", 6969);
            client.sendMessage("12345678",args[2]);
            client.sendMessage("ABCDEFGH",args[2]);
            client.sendMessage("87654321",args[2]);
            client.sendMessage("HGFEDCBA",args[2]);
            client.stopConnection();
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
        } catch (CertificateException e) {
            System.out.println("Invalid certificate. Please try again");
        } catch (KeyStoreException e) {
            System.out.println("Invalid key store instance. Please try again");
        } catch (UnrecoverableKeyException e) {
            System.out.println("Unrecoverable key. Please try again.");
        }
    }
}
