import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.util.HashMap;
import java.util.Map;


public class TransformedMapUseTest {

    public static void main(String[] args) {

        Map innerMap = new HashMap();

        Transformer transformer = new InvokerTransformer("func",
                new Class[]{String.class},
                new Object[]{"1"});

        innerMap.put("value", "value");
        Map<String, Object> outMap = org.apache.commons.collections.map.TransformedMap.decorate(innerMap, null, transformer);

        TestClass testClass = new TestClass();
        for(Map.Entry<String,Object> m: outMap.entrySet()){
            m.setValue(testClass);
        }
    }

}




