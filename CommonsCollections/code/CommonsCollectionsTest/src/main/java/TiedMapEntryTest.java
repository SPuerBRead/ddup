import org.apache.commons.collections.keyvalue.TiedMapEntry;

import java.util.HashMap;
import java.util.Map;

public class TiedMapEntryTest {

    public static void main(String[] args) {
        Map map = new HashMap();
        map.put("c",1);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map,"c");
        System.out.println(tiedMapEntry);
    }
}
