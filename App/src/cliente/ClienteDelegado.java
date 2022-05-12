package cliente;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;

public class ClienteDelegado extends Cliente {

    public ClienteDelegado(String id, int nPeticiones, PublicKey llavePublica, int idThread) {
        super(id, nPeticiones, llavePublica, idThread);
    }

    public static void main(String[] args) throws Exception {
        String[] nombres = {"Juliana", "Camila", "Daniel", "Boris", "Juan", "Sergio", "Cristian", "Pedro", "Jesus", "William", "Kevin"};
        Scanner sc = new Scanner(System.in);
        System.out.println("Ingrese la cantidad de delegados: ");
        int nDelegados = sc.nextInt();
        try {
            PublicKey llave = getPublicKey("keys", "RSA");

            // AppCliente clientes[] = new AppCliente[1];
            ClienteDelegado[] clientes = new ClienteDelegado[32];
            for (int i = 0; i < nDelegados; i++) {
                String nombreAleatorio = nombres[new Random().nextInt(nombres.length)];
                clientes[i] = new ClienteDelegado(nombreAleatorio, 1, llave, i);
                clientes[i].start();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }

    }
}
