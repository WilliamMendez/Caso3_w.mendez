package cliente;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Cliente extends Thread {

    private String nombre;
    private int nPeticiones;
    private PublicKey llavePublica;
    private int idThread;
    private static final String PADDING = "AES/ECB/PKCS5Padding";

    public Cliente(String nombre, int nPeticiones, PublicKey llavePublica, int idThread) {
        this.nombre = nombre;
        this.nPeticiones = nPeticiones;
        this.llavePublica = llavePublica;
        this.idThread = idThread;
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

    public static byte[] getDigest(String mensaje) {
        byte[] digest = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(mensaje.getBytes());
            digest = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest;
    }

    public static String hmacWithJava(String algorithm, byte[] data, SecretKey key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(key);
        return byte2str(mac.doFinal(data));
    }

    public void run() {
        try {
            for (int i = 0; i < nPeticiones; i++) {
                try {
                    Socket socketCliente = new Socket("localhost", 9090);
                    PrintWriter sOutput = new PrintWriter(socketCliente.getOutputStream(), true);
                    BufferedReader sInput = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
                    String inputLine;

                    String idPaquete = String.valueOf(idThread * 10 + i);

                    String mensaje = "";
                    mensaje += idThread + "_" + nombre + "_" + idPaquete;
                    System.out.println(mensaje + " Inicio");

                    // INICIO / ACK
                    sOutput.println(byte2str(cifrar(llavePublica, "INICIO", "RSA")));

                    inputLine = descifrar(llavePublica, str2byte(sInput.readLine()), "RSA");

                    if (!inputLine.equals("ACK")) {
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: ACK no recibido");
                    }

                    // reto / reto cifrado con privada
                    String numReto = getRandomNumber(24, new Random()).toString();
                    sOutput.println(byte2str(cifrar(llavePublica, numReto, "RSA")));
                    System.out.println(mensaje + " Reto enviado: " + numReto);

                    inputLine = sInput.readLine();
                    byte[] retoCifrado = str2byte(inputLine);
                    String retoDescifrado = descifrar(llavePublica, retoCifrado, "RSA");
                    System.out.println(mensaje + " Reto recibido: " + retoDescifrado);

                    if (!numReto.equals(retoDescifrado)) {
                        sOutput.println(byte2str(cifrar(llavePublica, "ERROR", "RSA")));
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: Reto no coincide");
                    }

                    // llave simetrica / ACK

                    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                    SecretKey secretKey = keyGenerator.generateKey();
                    byte[] llaveSimetrica = secretKey.getEncoded();
                    byte[] llaveSimetricaCifrada = cifrar(llavePublica, byte2str(llaveSimetrica), "RSA");
                    sOutput.println(byte2str(llaveSimetricaCifrada));
                    System.out.println(mensaje + " Llave simetrica enviada: " + byte2str(llaveSimetrica));

                    inputLine = descifrar(llavePublica, str2byte(sInput.readLine()), "RSA");

                    if (!inputLine.equals("ACK")) {
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: ACK no recibido");
                    }

                    // idCliente / ACK|ERROR
                    sOutput.println(byte2str(cifrar(llavePublica, nombre, "RSA")));

                    inputLine = descifrar(llavePublica, str2byte(sInput.readLine()), "RSA");

                    if (inputLine.equals("ACK")) {
                        System.out.println(mensaje + " Se encontró el cliente: " + nombre);
                    } else {
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: cliente no existe");
                    }

                    // idPaquete / respuesta de tabla cifrado con llave simetrica
                    sOutput.println(byte2str(cifrar(secretKey, idPaquete, PADDING)));

                    String estao = descifrar(secretKey, str2byte(sInput.readLine()), PADDING);

                    if (estao.equals("DESCONOCIDO")) {
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: El paquete no esta");
                    } else {
                        System.out.println(mensaje + " Estado del paquete: " + estao);
                    }

                    // ACK / HMAC(LS, digest(idCliente, idPaquete, respuesta))
                    sOutput.println(byte2str(cifrar(llavePublica, "ACK", "RSA")));

                    inputLine = descifrar(secretKey, str2byte(sInput.readLine()), PADDING);

                    if (!inputLine.equals("ERROR")) {
                        System.out.print(mensaje + " HMAC recibido: ");
                        System.out.println(inputLine);

                        String digest = "CLIENTE:" + nombre + "_PKT:" + idPaquete + "_ESTADO:" + estao;
                        byte[] digestBytes = getDigest(digest);
                        try {
                            String hmac = hmacWithJava("HmacSHA256", digestBytes, secretKey);
                            System.out.println(mensaje + " HMAC generado: " + hmac);
                            if (hmac.equals(inputLine)) {
                                System.out.println(mensaje + " HMAC correcto");
                            } else {
                                socketCliente.close();
                                sOutput.println(byte2str(cifrar(llavePublica, "ERROR", "RSA")));
                                throw new Exception(mensaje + " ERROR: HMAC incorrecto");
                            }
                        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                            socketCliente.close();
                            throw new Exception(mensaje + " ERROR: no se pudo generar el HMAC");
                        }

                    } else {
                        socketCliente.close();
                        throw new Exception(mensaje + " ERROR: No se recibio el HMAC");
                    }

                    // FIN
                    sOutput.println(byte2str(cifrar(llavePublica, "TERMINAR", "RSA")));
                    System.out.println(mensaje + " Fin");
                    socketCliente.close();

                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    ;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return;

    }

    private BigInteger getRandomNumber(int digCount, Random rnd) {
        final char[] ch = new char[digCount];
        for (int i = 0; i < digCount; i++) {
            ch[i] = (char) ('0' + (i == 0 ? rnd.nextInt(9) + 1 : rnd.nextInt(10)));
        }
        return new BigInteger(new String(ch));
    }

    public static String byte2str(byte[] b) {
        // Encapsulamiento con hexadecimales
        String ret = "";
        for (int i = 0; i < b.length; i++) {
            String g = Integer.toHexString(((char) b[i]) & 0x00ff);
            ret += (g.length() == 1 ? "0" : "") + g;
        }
        return ret;
    }

    public byte[] str2byte(String ss) {
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

}
