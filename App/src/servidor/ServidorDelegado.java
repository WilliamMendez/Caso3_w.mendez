package servidor;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServidorDelegado extends Servidor {
    private static final int PORT = 9090;

    public ServidorDelegado(Socket socketCliente) throws IOException {
        super(socketCliente);
    }

    public static void main(String[] args) throws Exception {
        poblarDatos();
        tipo = "Delegado";
        KeyPair keyPair;
        try {
            // keyPair = generateKey();
            keyPair = LoadKeyPair("keys", "RSA");
            Servidor.publicKey = keyPair.getPublic();
            Servidor.privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Scanner sc = new Scanner(System.in);
        System.out.println("Ingrese la cantidad de delegados: ");
        int cantDelegados = sc.nextInt();
        nDelegados = String.valueOf(cantDelegados);
        ExecutorService pool = Executors.newFixedThreadPool(cantDelegados);
        ServerSocket socket = null;
        try {
            socket = new ServerSocket(PORT);
            System.out.println("Servidor iniciado en el puerto " + PORT);
            while (true) {
                Socket socketCliente = socket.accept();
                pool.execute(new ServidorDelegado(socketCliente));

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        socket.close();
        pool.shutdown();
        sc.close();
    }
}
