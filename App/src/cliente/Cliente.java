package cliente;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Cliente extends Thread {

    private int id;
    private int nPeticiones;
    private PublicKey llavePublica;
    private static final String PADDING = "AES/ECB/PKCS5Padding";

    public Cliente(int id, int nPeticiones, PublicKey llavePublica) {
        this.id = id;
        this.nPeticiones = nPeticiones;
        this.llavePublica = llavePublica;
    }

    public static PublicKey getPublicKey(String path, String algorithm)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    public static byte[] cifrar(Key llave, String mensaje, String algoritmo) {
        byte[] mensajeCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            byte[] mensajeClaro = mensaje.getBytes();
            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            mensajeCifrado = cifrador.doFinal(mensajeClaro);
            return mensajeCifrado;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String descifrar(Key llave, byte[] mensajeCifrado, String algoritmo) {
        String mensajeDescifrado;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            byte[] mensajeClaro = cifrador.doFinal(mensajeCifrado);
            mensajeDescifrado = new String(mensajeClaro);
            return mensajeDescifrado;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void run() {
        try {
            for (int i = 1; i <= nPeticiones; i++) {
                System.out.println("-----------------------------------------------------");
                Socket socketCliente = new Socket("localhost", 9090);
                PrintWriter sOutput = new PrintWriter(socketCliente.getOutputStream(), true);
                BufferedReader sInput = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
                String inputLine;

                System.out.println("Cliente " + id);

                // INICIO / ACK
                sOutput.println(byte2str(cifrar(llavePublica, "INICIO", "RSA")));
                inputLine = sInput.readLine();
                if (inputLine.equals("ACK")) {
                    System.out.println("ACK recibido");
                } else {
                    System.out.println("ACK no recibido");
                    socketCliente.close();
                    return;
                }

                // reto / reto cifrado con privada
                String numReto = getRandomNumber(24, new Random()).toString();
                sOutput.println(byte2str( cifrar(llavePublica, numReto, "RSA")));
                inputLine = sInput.readLine();
                byte[] retoCifrado = str2byte(inputLine);
                String retoDescifrado = descifrar(llavePublica, retoCifrado, "RSA");
                System.out.println("Reto enviado: " + numReto);
                System.out.println("Reto recibido: " + retoDescifrado);
                if (!numReto.equals(retoDescifrado)) {
                    System.out.println("Reto no coincide");
                    sOutput.println(byte2str(cifrar(llavePublica, "ERROR", "RSA")));
                    socketCliente.close();
                    return;
                }

                // llave simetrica / ACK

                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                SecretKey secretKey = keyGenerator.generateKey();
                byte[] llaveSimetrica = secretKey.getEncoded();
                byte[] llaveSimetricaCifrada = cifrar(llavePublica, byte2str(llaveSimetrica), "RSA");
                sOutput.println(byte2str(llaveSimetricaCifrada));
                System.out.println("Llave simetrica enviada: " + byte2str(llaveSimetrica));
                inputLine = sInput.readLine();

                // idCliente / ACK|ERROR
                sOutput.println(byte2str(cifrar(llavePublica, String.valueOf(id), "RSA")));
                inputLine = sInput.readLine();
                if (inputLine.equals("ACK")) {
                    System.out.println("recibido:" + inputLine);
                } else {
                    System.out.println("ERROR: cliente no existe");
                    socketCliente.close();
                    return;
                }

                // idPaquete / respuesta de tabla cifrado con llave simetrica
                System.out.println("peticion " + i + " enviada");
                sOutput.println(byte2str(cifrar(secretKey, String.valueOf(i), PADDING)));
                inputLine = sInput.readLine();
                if (inputLine.equals("DESCONOCIDO")) {
                    System.out.println("el paquete no esta");
                    socketCliente.close();
                    return;
                } else {
                    System.out.println("recibido:" + inputLine);
                }

                // ACK / HMAC(LS, digest(idCliente, idPaquete, respuesta))
                sOutput.println(byte2str(cifrar(llavePublica, "ACK", "RSA")));
                inputLine = sInput.readLine();
                if (!inputLine.equals("ERROR")) {
                    System.out.print("info paq: ");
                    System.out.println(inputLine);
                } else {
                    System.out.println("ERROR: algo salio mal con el HMAC");
                    socketCliente.close();
                    return;
                }

                // FIN
                sOutput.println(byte2str(cifrar(llavePublica, "TERMINAR", "RSA")));
                socketCliente.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private BigInteger getRandomNumber(int digCount, Random rnd) {
        final char[] ch = new char[digCount];
        for (int i = 0; i < digCount; i++) {
            ch[i] = (char) ('0' + (i == 0 ? rnd.nextInt(9) + 1 : rnd.nextInt(10)));
        }
        return new BigInteger(new String(ch));
    }

    public String byte2str(byte[] b) {
        // Encapsulamiento con hexadecimales
        String ret = "";
        for (int i = 0; i < b.length; i++) {
            String g = Integer.toHexString(((char) b[i]) & 0x00ff);
            ret += (g.length() == 1 ? "0" : "") + g;
        }
        return ret;
    }

    public byte[] str2byte(String ss) {
        String[] byteValues = ss.substring(1, ss.length() - 1).split(",");
        byte[] bytes = new byte[byteValues.length];

        for (int i = 0, len = bytes.length; i < len; i++) {
            bytes[i] = Byte.parseByte(byteValues[i].trim());
        }
        return bytes;
    }

}
