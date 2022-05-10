import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;

public class AppCliente extends Thread {

    private int id;
    private int nPeticiones;

    public AppCliente(int id, int nPeticiones) {
        this.id = id;
        this.nPeticiones = nPeticiones;
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
                sOutput.println("INICIO");
                inputLine = sInput.readLine();
                if (inputLine.equals("ACK")) {
                    System.out.println("ACK recibido");
                } else {
                    System.out.println("ACK no recibido");
                    socketCliente.close();
                    return;
                }

                // reto / reto cifrado con privada
                BigInteger numReto = getRandomNumber(24, new Random());
                sOutput.println(numReto.toString());
                inputLine = sInput.readLine();
                BigInteger retoCifrado = new BigInteger(inputLine);
                
                // llave simetrica / ACK
                // idCliente / ACK|ERROR
                sOutput.println(id);
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
                sOutput.println(i);
                inputLine = sInput.readLine();
                if (inputLine.equals("DESCONOCIDO")) {
                    System.out.println("el paquete no esta");
                    socketCliente.close();
                    return;
                } else {
                    System.out.println("recibido:" + inputLine);
                }

                // ACK / HMAC(LS, digest(idCliente, idPaquete, respuesta))
                sOutput.println("ACK");
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
                sOutput.println("TERMINAR");
                socketCliente.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private BigInteger getRandomNumber(int digCount, Random random) {
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
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    public static void main(String[] args) throws Exception {
        String tipo;
        Scanner sc = new Scanner(System.in);
        System.out.println("Ingrese el tipo de conexion: \n(1) iterativo\n(2) delegado");
        tipo = sc.nextLine();
        if (tipo.equalsIgnoreCase("delegado") || tipo.equalsIgnoreCase("2")) {
            // AppCliente clientes[] = new AppCliente[1];
            AppCliente[] clientes = new AppCliente[32];
            for (int i = 0; i < clientes.length; i++) {
                clientes[i] = new AppCliente(i + 1, 1);
                clientes[i].start();
            }
        } else if (tipo.equalsIgnoreCase("iterativo") || tipo.equalsIgnoreCase("1")) {
            AppCliente cliente = new AppCliente(0, 32);
            cliente.start();
        }
        sc.close();
    }
}
