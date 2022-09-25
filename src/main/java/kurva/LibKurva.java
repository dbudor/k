package kurva;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.JavaCurve25519Provider;

public class LibKurva implements Kurva {
    Curve25519 c = Curve25519.getInstance(Curve25519.JAVA);
    private byte[] privateKey;
    private byte[] publicKey;

    @Override
    public void create() {
        Curve25519KeyPair kp = c.generateKeyPair();
        privateKey = kp.getPrivateKey();
        publicKey = kp.getPublicKey();
    }

    static class JavaCurve25519ProviderWithPublicConstructor extends JavaCurve25519Provider {
        public JavaCurve25519ProviderWithPublicConstructor() {
            super();
        }
    }

    @Override
    public void fromPrivateKey(byte[] priv) {
        this.privateKey = priv;
        JavaCurve25519Provider p = new JavaCurve25519ProviderWithPublicConstructor();
        this.publicKey = p.generatePublicKey(priv);
    }

    @Override
    public byte[] keyAgreement(byte[] pub) {
        return c.calculateAgreement(pub, privateKey);
    }

    @Override
    public byte[] getPublicKey() {
        return publicKey;
    }

    @Override
    public byte[] getPrivateKey() {
        return privateKey;
    }

}
