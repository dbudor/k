package kurva;

import org.junit.Assert;
import org.junit.Test;

public class KurvaTest {

    public void testKurva(Class<? extends Kurva> clazz1, Class<? extends Kurva> clazz2) throws Exception {
        Kurva kurva1 = clazz1.newInstance();
        Kurva kurva2 = clazz2.newInstance();
        kurva1.create();
        kurva2.create();
        byte[] secret1 = kurva1.keyAgreement(kurva2.getPublicKey());
        byte[] secret2 = kurva2.keyAgreement(kurva1.getPublicKey());
        Assert.assertArrayEquals(secret1, secret2);
    }

    @Test
    public void lib2lib() throws Exception {
        testKurva(LibKurva.class, LibKurva.class);
    }

    @Test
    public void lib2bouncy() throws Exception {
        testKurva(LibKurva.class, BouncyKurva.class);
    }

    @Test
    public void bouncy2bouncy() throws Exception {
        testKurva(BouncyKurva.class, BouncyKurva.class);
    }

    @Test
    public void bouncylib() throws Exception {
        testKurva(BouncyKurva.class, LibKurva.class);
    }

}