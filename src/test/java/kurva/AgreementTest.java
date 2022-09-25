package kurva;

import org.junit.Assert;
import org.junit.Test;

public class AgreementTest {

    public void testKurva(Class<? extends Kurva> clazz1, Class<? extends Kurva> clazz2) throws Exception {
        Kurva kurva1 = clazz1.newInstance();
        Kurva kurva2 = clazz2.newInstance();
        kurva1.create();
        kurva2.create();
        byte[] publicKey1 = kurva1.getPublicKey();
        byte[] privateKey1 = kurva1.getPrivateKey();
        byte[] publicKey2 = kurva2.getPublicKey();
        byte[] privateKey2 = kurva2.getPrivateKey();

        System.out.printf("%s -> %s\n", clazz1.getSimpleName(), clazz2.getSimpleName());
        System.out.printf("1 pri: %s\n", Hex.encodeHex(privateKey1));
        System.out.printf("1 pub: %s\n", Hex.encodeHex(publicKey1));
        System.out.printf("2 pri: %s\n", Hex.encodeHex(privateKey2));
        System.out.printf("2 pub: %s\n", Hex.encodeHex(publicKey2));

        byte[] secret1 = kurva1.keyAgreement(publicKey2);
        byte[] secret2 = kurva2.keyAgreement(publicKey1);
        System.out.printf("1 sec: %s\n", Hex.encodeHex(secret1));
        System.out.printf("2 sec: %s\n", Hex.encodeHex(secret2));
        System.out.println();
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
    public void bouncy2lib() throws Exception {
        testKurva(BouncyKurva.class, LibKurva.class);
    }

    @Test
    public void x255192lib() throws Exception {
        testKurva(X25519Kurva.class, LibKurva.class);
    }

    @Test
    public void lib2x25519() throws Exception {
        testKurva(LibKurva.class, X25519Kurva.class);
    }

}