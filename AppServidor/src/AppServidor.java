import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.KeyGenerator;

public class AppServidor extends Thread {
    private static final int PORT = 9090;
    private static HashMap<String, HashMap<String, String>> datos = new HashMap<String, HashMap<String, String>>();
    private PrintWriter sOutput;
    private BufferedReader sInput;
    private Socket socketCliente;

    public AppServidor(Socket socketCliente) throws IOException {
        this.socketCliente = socketCliente;
    }

    public static void procesar(BufferedReader sInput, PrintWriter sOutput, Socket socketCliente) throws IOException {
        sOutput = new PrintWriter(socketCliente.getOutputStream(), true);
        sInput = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
        String inputLine;

        System.out.println("-----------------------------------------------------");

        // INICIO / ACK
        inputLine = sInput.readLine();
        if (inputLine.equals("INICIO")) {
            sOutput.println("ACK");
        } else {
            sOutput.println("ERROR");
            socketCliente.close();
            return;
        }
        // reto / reto cifrado con privada
        // llave simetrica / ACK
        // idCliente / ACK|ERROR
        inputLine = sInput.readLine();
        System.out.println("cliente: " + inputLine + " conectado");

        HashMap<String, String> datosCliente;
        if (datos.containsKey(inputLine)) {
            System.out.println("cliente existe");
            sOutput.println("ACK");
            datosCliente = datos.get(inputLine);
        } else {
            System.out.println("cliente no existe");
            sOutput.println("ERROR");
            socketCliente.close();
            return;
        }

        // idPaquete / respuesta de tabla cifrado con llave simetrica

        inputLine = sInput.readLine();
        if (datosCliente.containsKey(inputLine)) {
            System.out.println("paquete "+ inputLine + " existe" + " con estado: " + datosCliente.get(inputLine));
            sOutput.println(datosCliente.get(inputLine));
        } else {
            System.out.println("paquete "+ inputLine + " no existe");
            sOutput.println("DESCONOCIDO");
            socketCliente.close();
            return;
        }

        // ACK / HMAC(LS, digest(idCliente, idPaquete, respuesta))

        inputLine = sInput.readLine();
        if (inputLine.equals("ACK")) {
            System.out.println("ACK recibido");
        } else {
            System.out.println("ERROR");
            socketCliente.close();
            return;
        }
        sOutput.println("HMAC");

        // FIN
        inputLine = sInput.readLine();
        if (inputLine.equals("TERMINAR")) {
            System.out.println("terminado");
        } else {
            System.out.println("ERROR");
        }
        socketCliente.close();
        return;

    }

    @Override
    public void run() {
        // TODO Auto-generated method stub
        try {
            procesar(sInput, sOutput, socketCliente);
        } catch (IOException e) {
            e.printStackTrace();
        }
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
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    public static void main(String[] args) throws Exception {
        // Generacion de datos
        String[] estados = {"PKT_EN_OFICINA", "PKT_RECOGIDO", "PKT_EN_CLASIFICACION", "PKT_DESPACHADO",
        "PKT_EN_ENTREGA", "PKT_ENTREGADO", "PKT_DESCONOCIDO"};

        for (int i = 0; i < 32; i++) {
            HashMap<String, String> datosCliente = new HashMap<String, String>();
            for (int j = 0; j < 32; j++) {
                int estado = new Random().nextInt(estados.length);
                datosCliente.put(Integer.toString(j), estados[estado]);
            }
            datos.put(Integer.toString(i), datosCliente);
        }

        // KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // keyPairGenerator.initialize(1024);
        // KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // PrivateKey privateKey = keyPair.getPrivate();
        // PublicKey publicKey = keyPair.getPublic();
        // System.out.println("privateKey: " + privateKey);
        // System.out.println("publicKey: " + publicKey);

        PublicKey privateKeyCliente = PublicKey.class.cast(blockerLock);

        String tipo;
        Scanner sc = new Scanner(System.in);
        System.out.println("Ingrese el tipo de conexion: \n(1) iterativo\n(2) delegado");
        tipo = sc.nextLine();
        if (tipo.equalsIgnoreCase("delegado") || tipo.equalsIgnoreCase("2")) {
            System.out.println("Ingrese la cantidad de delegados: ");
            int cantDelegados = sc.nextInt();
            ExecutorService pool = Executors.newFixedThreadPool(cantDelegados);
            ServerSocket socket = null;
            try {
                socket = new ServerSocket(PORT);
                System.out.println("Servidor iniciado en el puerto " + PORT);
                while (true) {
                    Socket socketCliente = socket.accept();
                    pool.execute(new AppServidor(socketCliente));

                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            socket.close();
            pool.shutdown();
        } else if (tipo.equalsIgnoreCase("iterativo") || tipo.equalsIgnoreCase("1")) {
            ServerSocket socket = null;
            try {
                socket = new ServerSocket(PORT);
                System.out.println("Servidor iniciado en el puerto " + PORT);
                while (true) {
                    Socket socketCliente = socket.accept();
                    try {
                        PrintWriter sOutput = new PrintWriter(socketCliente.getOutputStream(), true);
                        BufferedReader sInput = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
                        procesar(sInput, sOutput, socketCliente);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            socket.close();
        } else {
            System.out.println("Ingrese un tipo de conexion valido");
        }
        sc.close();
    }
}
