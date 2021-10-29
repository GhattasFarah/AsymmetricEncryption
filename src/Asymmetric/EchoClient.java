package part1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoClient {
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyPair kPair;
    private PublicKey serverKey;

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
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, SignatureException {
        System.out.println("Client sending cleartext "+msg);
        byte[] data = msg.getBytes("UTF-8");

        //setting up the cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverKey);
        byte[] cipherBytes = cipher.doFinal(data);

        //signing the bytes with the secret key
        Signature signOut = Signature.getInstance("SHA256withRSA");
        signOut.initSign(kPair.getPrivate());
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
        cipher.init(Cipher.DECRYPT_MODE, kPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(received);
        String reply = new String(decryptedBytes, "UTF-8");
        System.out.println("Server returned cleartext "+reply);

        //authenticating using servers public key
        Signature signIn = Signature.getInstance("SHA256withRSA");
        signIn.initVerify(serverKey);
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
     * This method generates the client keypair and asks for the server public key to store
     */
    public void generatekeys() throws NoSuchAlgorithmException, InvalidKeySpecException{
        Base64.Encoder en = Base64.getEncoder();
        //generating the public and private keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kPair = kpg.generateKeyPair(); //generating and storing the keypair

        System.out.println("Public key for client="+ en.encodeToString(kPair.getPublic().getEncoded()));

        //this segment is to convert the public key back from the encoded version
        System.out.print("Please enter server public key:");
        Scanner sc = new Scanner(System.in);
        String processing = sc.nextLine();
        sc.close();

        //converting the byte to public key
        byte[] g = Base64.getDecoder().decode(processing);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(g);
        serverKey = KeyFactory.getInstance("RSA").generatePublic(spec); //storing server public key
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
            client.generatekeys(); //generates the keys

            client.startConnection("127.0.0.1", 6969);
            client.sendMessage("12345678");
            client.sendMessage("ABCDEFGH");
            client.sendMessage("87654321");
            client.sendMessage("HGFEDCBA");
            client.stopConnection();
        }catch (NoSuchAlgorithmException e){
            System.out.println("Algorithm can't be found. Please enter again");
        }catch (InvalidKeySpecException i){
            System.out.println("Invalid key enter. Please enter a valid key");
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
        }
    }
}
