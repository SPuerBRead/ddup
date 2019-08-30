import javassist.*;

import java.io.IOException;

public class JavassistTest {

    public class Test{
        public void t(String a){
            System.out.println(a);
        }
    }

    public static void main(String[] args) throws CannotCompileException, NotFoundException, IOException {

        ClassPool classPool  = ClassPool.getDefault();
        CtClass ctClass = classPool.makeClass("target.classes.JavassistTestClass");
        CtMethod ctMethod = CtNewMethod.make("public void func(String a) { System.out.print(a); }", ctClass);
        ctClass.addMethod(ctMethod);
        String string = "java.lang.Runtime.getRuntime().exec(\"open /Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertAfter(string);
        CtClass superClass = classPool.get(Test.class.getName());
        ctClass.setSuperclass(superClass);
        ctClass.writeFile();
    }
}
