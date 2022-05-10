package cliente;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class ClienteDelegado extends Cliente {

    public ClienteDelegado(int id, int nPeticiones, PublicKey llavePublica) {
        super(id, nPeticiones, llavePublica);
    }

    public static void main(String[] args) throws Exception {
        try {
            PublicKey llave = getPublicKey("keys", "RSA");

            // AppCliente clientes[] = new AppCliente[1];
            ClienteDelegado[] clientes = new ClienteDelegado[32];
            for (int i = 0; i < clientes.length; i++) {
                clientes[i] = new ClienteDelegado(i + 1, 1, llave);
                clientes[i].start();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }

    }
}
