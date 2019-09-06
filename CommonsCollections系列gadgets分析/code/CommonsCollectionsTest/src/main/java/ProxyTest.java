
import java.lang.reflect.Proxy;

public class ProxyTest {

    public static void main(String[] args) {
        TestInterface testInterface = (TestInterface) Proxy.newProxyInstance(TestClass.class.getClassLoader(),TestClass.class.getInterfaces(), new TestInvocationHandler(new TestClass()));
        testInterface.func("a");
    }

}
