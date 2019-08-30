import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class TestInvocationHandler implements InvocationHandler {


    private final TestClass testClass;

    public TestInvocationHandler(TestClass testClass) {
        this.testClass = testClass;
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        System.out.println(method.getName());
        return null;
    }
}
