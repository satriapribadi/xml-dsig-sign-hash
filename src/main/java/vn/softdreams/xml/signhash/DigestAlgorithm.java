package vn.softdreams.xml.signhash;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.security.NoSuchAlgorithmException;

/**
 * Created by chen on 7/24/17.
 */
public enum DigestAlgorithm {

    SHA1("SHA-1", "1.3.14.3.2.26", DigestMethod.SHA1, SignatureMethod.RSA_SHA1),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1", DigestMethod.SHA256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", DigestMethod.SHA512, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");

    private String name;

    private String oid;

    private String hashMethod;

    private String signatureMethod;

    private DigestAlgorithm(String name, String oid, String hashMethod, String signatureMethod) {
        this.name = name;
        this.oid = oid;
        this.hashMethod = hashMethod;
        this.signatureMethod = signatureMethod;
    }

    /**
     * Return the algorithm corresponding to the name
     *
     * @param algoName
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static DigestAlgorithm getByName(String algoName) throws NoSuchAlgorithmException {
        if ("SHA-1".equals(algoName) || "SHA1".equals(algoName)) {
            return SHA1;
        }
        if ("SHA-256".equals(algoName)) {
            return SHA256;
        }
        if ("SHA-512".equals(algoName)) {
            return SHA512;
        }
        throw new NoSuchAlgorithmException("unsupported algo: " + algoName);
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the xmlId
     */
    public String getHashMethod() {
        return hashMethod;
    }

    public String getSignatureMethod() {
        return signatureMethod;
    }

    /**
     * Gets the ASN.1 algorithm identifier structure corresponding to this digest algorithm
     *
     * @return the AlgorithmIdentifier
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        /*
         * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations
         * still expect a NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the
         * recommendation, because the RFC states that implementations SHOULD support it as well anyway
         */
        return new AlgorithmIdentifier(new DERObjectIdentifier(this.getOid()), new DERNull());
    }

}