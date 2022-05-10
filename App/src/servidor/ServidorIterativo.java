package servidor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

public class ServidorIterativo extends Servidor {
    private static final int PORT = 9090;

    public ServidorIterativo(Socket socketCliente) throws IOException {
        super(socketCliente);
    }

    public static void main(String[] args) throws Exception {
        poblarDatos();
        tipo = "Iterativo";
        KeyPair keyPair;
        try {
            keyPair = LoadKeyPair("keys", "RSA");
            Servidor.publicKey = keyPair.getPublic();
            Servidor.privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }

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
    }

}
