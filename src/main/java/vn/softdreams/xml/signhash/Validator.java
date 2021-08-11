package vn.softdreams.xml.signhash;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

public class Validator {
    public boolean verify(InputStream is) throws Exception {

        // Instantiate the document to be validated
        DocumentBuilderFactory dbf2 = DocumentBuilderFactory.newInstance();
        dbf2.setNamespaceAware(true);
        Document doc2 = dbf2.newDocumentBuilder().parse(is);

        // Find Signature element
        NodeList nl = doc2.getElementsByTagName("ds:Signature");
        if (nl.getLength() == 0) {
            return false;
        }
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(2));
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        return signature.validate(valContext);
    }

    public boolean verify(String xmlFile) throws Exception {
        File fXml2 = new File(xmlFile);
        FileInputStream fis = new FileInputStream(fXml2);
        return verify(fis);
    }

    class KeyValueKeySelector extends KeySelector {

        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof X509Data) {
                    X509Data x509Data = (X509Data) xmlStructure;
                    Iterator xi = x509Data.getContent().iterator();
                    while (xi.hasNext()) {
                        Object o = xi.next();
                        if ((o instanceof X509Certificate)) {
                            final PublicKey pk = ((X509Certificate) o).getPublicKey();
                            if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                                return new SimpleKeySelectorResult(pk);
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA")
                    && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
                return true;
            } else if (algName.equalsIgnoreCase("RSA")
                    && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
                return true;
            } else {
                return false;
            }
        }
    }

    class SimpleKeySelectorResult implements KeySelectorResult {

        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return pk;
        }
    }
}
