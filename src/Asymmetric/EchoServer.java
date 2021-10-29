package part1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
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
    private KeyPair kPair;
    private PublicKey clientKey;


    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
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
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, kPair.getPrivate());

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
            signOut.initSign(kPair.getPrivate());
            signOut.update(decryptedBytes);
            byte[] signedBytes = signOut.sign();

            out.write(cipherBytes);
            out.write(signedBytes);
            out.flush();
        }
        stop();
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

    /**
     * This is the method to generate public and private keys
     */
    public void generateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException{
        Base64.Encoder en = Base64.getEncoder();
        //authenticate then encrypt

        //generating the public and private keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kPair = kpg.generateKeyPair();

        System.out.println("Public key for server="+ en.encodeToString(kPair.getPublic().getEncoded()));

        //this segment is to convert the public key back from the encoded version
        System.out.print("Please enter client public key:");
        Scanner sc = new Scanner(System.in);
        String processing = sc.nextLine();
        sc.close();

        //converting the byte to public key
        byte[] g = Base64.getDecoder().decode(processing);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(g);
        clientKey = KeyFactory.getInstance("RSA").generatePublic(spec); //storing server public key
    }

    public static void main(String[] args){
        EchoServer server = new EchoServer();
        try {
            server.generateKeys();
            server.start(6969);
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



