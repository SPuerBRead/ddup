import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient {
    public static void main(String[] args) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("10.10.37.77",1099);
        RMIServiceInterface rmiObject = (RMIServiceInterface) registry.lookup("getRandom");
        System.out.println(rmiObject.getRandomNumber());
    }
}
