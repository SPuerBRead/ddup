import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Random;

public class RMIServiceClass extends UnicastRemoteObject implements RMIServiceInterface{

    static {
        System.out.println("static code");
    }

    protected RMIServiceClass() throws RemoteException {
    }

    public int getRandomNumber() {
        Random r = new Random();
        int a = r.nextInt(100) % 50;
        System.out.println(a);
        return a;
    }
}
