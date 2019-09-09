import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import java.util.Properties;

public class JNDIClass {
    public static void main(String[] args) throws NamingException, RemoteException {
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        Context ctx = new InitialContext(env);
        //RMIServiceInterface RMIObject = (RMIServiceInterface) ctx.lookup("rmi://10.10.37.77:1099/getRandom");
        //System.out.println(RMIObject.getRandomNumber());

        RMIServiceInterface referenceTestObject = (RMIServiceInterface) ctx.lookup("rmi://10.10.37.77:1099/referenceTest");
    }
}
