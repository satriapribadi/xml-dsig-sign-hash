package vn.softdreams.xml.signhash;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

public class HashOperator {
    private final Document inputDoc;
    private final X509Certificate cert;
    private final String signingTagId;
    private final String signingTagName;
    private final String namespacePrefix;
    private final boolean usingNS;
    private final DigestAlgorithm hashAlgo;
    private Node sigParentNode;

    public HashOperator(Document inputDoc,
                        X509Certificate cert,
                        String signingTagId,
                        String signingTagName,
                        String namespacePrefix) {
        this.inputDoc = inputDoc;
        this.cert = cert;
        this.signingTagId = signingTagId;
        this.signingTagName = signingTagName;
        this.namespacePrefix = namespacePrefix;
        this.usingNS = !namespacePrefix.isEmpty();
        hashAlgo = DigestAlgorithm.SHA256;
        Init.init();
    }

    //Kiểm tra thẻ cần ký hợp lệ hay chưa, và tìm parent để add thẻ signature vào cùng level với thẻ cần ký
    private void checkValidDoc() throws Exception {
        if (inputDoc == null) throw new Exception("Document is null");
        if (signingTagId == null || signingTagId.isEmpty()) {
            sigParentNode = inputDoc.getChildNodes().item(1);
        } else {
            NodeList nl = inputDoc.getElementsByTagName(signingTagName);
            if (nl.getLength() == 0) throw new Exception("Xml tag with name = " + signingTagName + " not exist");
            if (nl.getLength() > 1) throw new Exception("More than 1 xml tag with name = " + signingTagName);
            Node processingNode = nl.item(0);
//            if (!processingNode.getAttributes().getNamedItem("ID").getTextContent().equals(signingTagId))
//                throw new Exception("SigningTagName and SigningTagId are not valid");
            sigParentNode = processingNode.getParentNode();
        }
    }

    public DigestAlgorithm getHashAlgo() {
        return hashAlgo;
    }

    private Element prepareSignature() throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        Element sigElement = doc.createElement("Signature");
        sigElement.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

        Element signedInfo = doc.createElement("SignedInfo");
        Element canonicalizationMethod = doc.createElement("CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm",
                usingNS ?
                        "http://www.w3.org/2001/10/xml-exc-c14n#" :
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        signedInfo.appendChild(canonicalizationMethod);
        Element signatureMethod = doc.createElement("SignatureMethod");
        signatureMethod.setAttribute("Algorithm", hashAlgo.getSignatureMethod());
        signedInfo.appendChild(signatureMethod);

        Element reference = doc.createElement("Reference");
        reference.setAttribute("URI", signingTagId == null || signingTagId.isEmpty() ? "" : "#" + signingTagId);
        signedInfo.appendChild(reference);
        Element transforms = doc.createElement("Transforms");
        Element transform1 = doc.createElement("Transform");
        transform1.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transforms.appendChild(transform1);
        if (usingNS) {
            Element transform2 = doc.createElement("Transform");
            transform2.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
            transforms.appendChild(transform2);
        }

        reference.appendChild(transforms);

        Element digestMethod = doc.createElement("DigestMethod");
        digestMethod.setAttribute("Algorithm", hashAlgo.getHashMethod());
        reference.appendChild(digestMethod);
        Element digestValue = doc.createElement("DigestValue");
        digestValue.setTextContent(getDigestForRemote());
        reference.appendChild(digestValue);
        signedInfo.appendChild(reference);
        sigElement.appendChild(signedInfo);

        Element signatureValue = doc.createElement("SignatureValue");
        sigElement.appendChild(signatureValue);

        Element keyInfo = doc.createElement("KeyInfo");
        Element x509Data = doc.createElement("X509Data");
        Element x509Certificate = doc.createElement("X509Certificate");
        x509Certificate.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);
        sigElement.appendChild(keyInfo);

        doc.appendChild(sigElement);
        return sigElement;
    }

    public HashResponse performDigest() throws Exception {
        checkValidDoc();
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        Element signature = prepareSignature();
        Element tmpNode = (Element) inputDoc.importNode(signature, true);
        sigParentNode.appendChild(tmpNode);

        Node signedInfo = signature.getElementsByTagName("SignedInfo").item(0);
        Element signedInfoEle = (Element) doc.importNode(signedInfo, true);
        signedInfoEle.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        doc.appendChild(signedInfoEle);

        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(doc);
        byte[] hash = DigestCreator.digest(transformed, hashAlgo);
        String sessionId = UUID.randomUUID().toString();
        Cache.getInstance().set(sessionId, inputDoc);
        return new HashResponse(sessionId, Base64.getEncoder().encodeToString(hash));
    }

    private String getDigestForRemote() throws Exception {
        Node nodeToBeHash = inputDoc.getElementsByTagName(signingTagName).item(0);

        Canonicalizer c14n = usingNS ?
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS) :
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(nodeToBeHash);

        return Base64.getEncoder().encodeToString(DigestCreator.digest(transformed, hashAlgo));
    }

    static class HashResponse {

        private final String hash;
        private Document tempDoc;
        private String id;

        public String getHash() {
            return hash;
        }

        public Document getTempDoc() {
            return tempDoc;
        }

        public String getId() {
            return id;
        }

        public HashResponse(String id, String hash) {
            this.hash = hash;
            this.id = id;
        }

        public HashResponse(String hash, Document tempDoc) {
            this.hash = hash;
            this.tempDoc = tempDoc;
        }
    }
}
