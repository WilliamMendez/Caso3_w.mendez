package cliente;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class ClienteIterativo extends Cliente {

    public ClienteIterativo(String nombre, int nPeticiones, PublicKey llavePublica, int idThread) {
        super(nombre, nPeticiones, llavePublica, idThread);
    }

    public static void main(String[] args) throws Exception {
        try {
            PublicKey llave = getPublicKey("keys", "RSA");
            // ClienteIterativo cliente = new ClienteIterativo("William", 32, llave);
            ClienteIterativo cliente = new ClienteIterativo("William", 32, llave, 8);
            cliente.start();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
    }
}
