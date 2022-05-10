package cliente;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class ClienteIterativo extends Cliente {

    public ClienteIterativo(int id, int nPeticiones, PublicKey llavePublica) {
        super(id, nPeticiones, llavePublica);
    }

    public static void main(String[] args) throws Exception {
        try {
            PublicKey llave = getPublicKey("keys", "RSA");
            ClienteIterativo cliente = new ClienteIterativo(0, 32, llave);
            // ClienteIterativo cliente = new ClienteIterativo(0, 1, llave);
            cliente.start();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
    }
}
