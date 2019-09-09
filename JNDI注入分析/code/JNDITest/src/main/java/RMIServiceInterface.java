import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMIServiceInterface extends Remote {
    public int getRandomNumber() throws RemoteException;
}
