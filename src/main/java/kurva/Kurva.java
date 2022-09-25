package kurva;

public interface Kurva {

    void create() throws Exception;

    void fromPrivateKey(byte[] privateKey) throws Exception;

    byte[] keyAgreement(byte[] publicKey) throws Exception;

    byte[] getPublicKey();

    byte[] getPrivateKey();

}
