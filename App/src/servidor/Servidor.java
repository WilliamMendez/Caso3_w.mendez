package servidor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Servidor extends Thread {
    private static HashMap<String, HashMap<String, String>> datos = new HashMap<String, HashMap<String, String>>();
    private static final String PADDING = "AES/ECB/PKCS5Padding";
    protected static String tipo;
    protected static String nDelegados = "";
    private PrintWriter sOutput;
    private BufferedReader sInput;
    private Socket socketCliente;
    protected static PublicKey publicKey;
    protected static PrivateKey privateKey;

    public Servidor(Socket socketCliente) throws IOException {
        this.socketCliente = socketCliente;
    }

    public static void poblarDatos() {
        String[] estados = { "PKT_EN_OFICINA", "PKT_RECOGIDO", "PKT_EN_CLASIFICACION", "PKT_DESPACHADO",
                "PKT_EN_ENTREGA", "PKT_ENTREGADO", "PKT_DESCONOCIDO" };

        // Generamos los datos
        for (int i = 0; i < 32; i++) {
            HashMap<String, String> datosCliente = new HashMap<String, String>();
            for (int j = 0; j < 32; j++) {
                int estado = new Random().nextInt(estados.length);
                datosCliente.put(Integer.toString(j), estados[estado]);
            }
            datos.put(Integer.toString(i), datosCliente);
        }
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

    public static KeyPair generateKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public static KeyPair LoadKeyPair(String path, String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static void procesar(BufferedReader sInput, PrintWriter sOutput, Socket socketCliente) throws IOException {
        sOutput = new PrintWriter(socketCliente.getOutputStream(), true);
        sInput = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
        String inputLine;

        System.out.println("-----------------------------------------------------");

        // INICIO / ACK
        inputLine = descifrar(privateKey, str2byte(sInput.readLine()), "RSA");
        if (inputLine.equals("INICIO")) {
            System.out.println("INICIO");
            sOutput.println(byte2str(cifrar(privateKey, "ACK", "RSA")));
        } else {
            sOutput.println(byte2str(cifrar(privateKey, "ERROR", "RSA")));
            socketCliente.close();
            return;
        }
        // reto / reto cifrado con privada
        String retoStr = descifrar(privateKey, str2byte(sInput.readLine()), "RSA");
        System.out.println("reto recibido: " + retoStr);

        long tiempoInicio = System.nanoTime();
        String retoCifrado = byte2str(cifrar(privateKey, retoStr, "RSA"));
        long tiempoFin = System.nanoTime();

        sOutput.println(retoCifrado);

        // llave simetrica / ACK
        byte[] simetrica = str2byte(sInput.readLine());
        inputLine = descifrar(privateKey, simetrica, "RSA");

        byte[] llaveSimetrica = str2byte(inputLine);
        System.out.println("llave simetrica recibida: " + byte2str(llaveSimetrica));
        SecretKey llaveSimetricaKey = new SecretKeySpec(llaveSimetrica, "AES");

        sOutput.println(byte2str(cifrar(privateKey, "ACK", "RSA")));

        // probar cifrado simetrico
        long tiempoInicio2 = System.nanoTime();
        String mensajeCifrado = byte2str(cifrar(llaveSimetricaKey, retoStr, PADDING));
        long tiempoFin2 = System.nanoTime();

        System.out.println("Tiempo de cifrado asimetrico: " + (tiempoFin - tiempoInicio) + " nanosegundos\n"
                         + "Tiempo de cifrado simetrico: " + (tiempoFin2 - tiempoInicio2) + " nanosegundos");
        long[] tiempos = {tiempoFin - tiempoInicio, tiempoFin2 - tiempoInicio2};
        guardar(tiempos);


        // idCliente / ACK|ERROR
        String idCliente = descifrar(privateKey, str2byte(sInput.readLine()), "RSA");

        HashMap<String, String> datosCliente;
        if (datos.containsKey(idCliente)) {
            System.out.println("cliente " + idCliente + " existe");
            sOutput.println(byte2str(cifrar(privateKey, "ACK", "RSA")));
            datosCliente = datos.get(idCliente);
        } else {
            System.out.println("cliente " + idCliente + " no existe");
            sOutput.println(byte2str(cifrar(privateKey, "ERROR", "RSA")));
            socketCliente.close();
            return;
        }

        // idPaquete / respuesta de tabla cifrado con llave simetrica

        String idPaquete = descifrar(llaveSimetricaKey, str2byte(sInput.readLine()), PADDING);

        if (datosCliente.containsKey(idPaquete)) {
            System.out.println("paquete " + idPaquete + " existe" + " con estado: " + datosCliente.get(idPaquete));
            sOutput.println(byte2str(cifrar(llaveSimetricaKey, datosCliente.get(idPaquete), PADDING)));
        } else {
            System.out.println("paquete " + idPaquete + " no existe");
            sOutput.println(byte2str(cifrar(llaveSimetricaKey, "DESCONOCIDO", PADDING)));
            socketCliente.close();
            return;
        }

        // ACK / HMAC(LS, digest(idCliente, idPaquete, respuesta))

        inputLine = descifrar(privateKey, str2byte(sInput.readLine()), "RSA");
        if (!inputLine.equals("ACK")) {
            System.out.println("ERROR: el cliente encontró error en la respuesta del paquete");
            socketCliente.close();
            return;
        }
        sOutput.println(byte2str(cifrar(llaveSimetricaKey,
                ("CLIENTE:" + idCliente + "_PKT:" + idPaquete + "_ESTADO:" + datosCliente.get(idPaquete)), PADDING)));

        // FIN
        inputLine = descifrar(privateKey, str2byte(sInput.readLine()), "RSA");
        if (inputLine.equals("TERMINAR")) {
            System.out.println("FIN");
        } else {
            System.out.println("ERROR: El cliente envio algo inesperado");
        }
        socketCliente.close();
        return;

    }

    private static void guardar(long[] tiempos) {
        try {
            FileWriter fichero = new FileWriter("docs/tiempos" + tipo + nDelegados + ".csv", true);
            BufferedWriter bw = new BufferedWriter(fichero);
            PrintWriter pw = new PrintWriter(bw);
            pw.println(tiempos[0] + ";" + tiempos[1]);
            pw.close();
        } catch (IOException e) {
            System.out.println("Error al escribir en el archivo");
        }
    }

    @Override
    public void run() {
        try {
            procesar(sInput, sOutput, socketCliente);
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    public static byte[] str2byte(String ss) {
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }
}
