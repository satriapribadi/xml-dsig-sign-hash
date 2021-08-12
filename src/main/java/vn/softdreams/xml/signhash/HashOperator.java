package vn.softdreams.xml.signhash;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

public class HashOperator {
    private final String HASH_ALGO = "SHA-1";
    private final String HASH_ALGO_OID = "1.3.14.3.2.26";
    //xml chưa ký
    private Document inputDoc;

    //Thông tin chứng thư số test
    private X509Certificate cert;

    //Thông tin định dạng file xml đầu vào
    //Id của tag cha của tag cần ký
    private String signedTagId;
    //Id của tag signature
    private String signingTagId;
    //Namespace của file cần ký, inv:invoiceData -> namespace = inv
    private String namespacePrefix;

    public HashOperator(Document inputDoc, X509Certificate cert, String signedTagId, String signingTagId, String namespacePrefix) {
        this.inputDoc = inputDoc;
        this.cert = cert;
        this.signedTagId = signedTagId;
        this.signingTagId = signingTagId;
        this.namespacePrefix = namespacePrefix;
        Init.init();
    }

    private Element prepareSignature() throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        //root signature node
        Element sigElement = doc.createElement("ds:Signature");
        Attr sigIdAttr = doc.createAttribute("Id");
        sigIdAttr.setValue(signingTagId);
        sigElement.setAttributeNode(sigIdAttr);
//        Attr xmlnsAttr = doc.createAttribute("xmlns");
//        xmlnsAttr.setValue("http://www.w3.org/2000/09/xmldsig#");
//        sigElement.setAttributeNode(xmlnsAttr);

        //signedInfo node
        Element signedInfo = doc.createElement("ds:SignedInfo");
        //signedInfo-canonicalizationMethod node
        Element canonicalizationMethod = doc.createElement("ds:CanonicalizationMethod");
        Attr algoAttr = doc.createAttribute("Algorithm");
        //TODO: kiểm tra lại trường hợp có namespace prefix, tạm thời fix theo Cyber
//        if (namespacePrefix != null && !namespacePrefix.isEmpty()) {
//            algoAttr.setValue("http://www.w3.org/2001/10/xml-exc-c14n#");
//        } else {
//            algoAttr.setValue("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
//        }
        algoAttr.setValue("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        canonicalizationMethod.setAttributeNode(algoAttr);
        signedInfo.appendChild(canonicalizationMethod);
        //signedInfo-SignatureMethod node
        Element signatureMethod = doc.createElement("ds:SignatureMethod");
        Attr sigAlgoAttr = doc.createAttribute("Algorithm");
        sigAlgoAttr.setValue("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        signatureMethod.setAttributeNode(sigAlgoAttr);
        signedInfo.appendChild(signatureMethod);

        //SignedInfo-Reference node
        Element reference = doc.createElement("ds:Reference");
        Attr uriAttr = doc.createAttribute("URI");
        //TODO: đang fix lại theo Cyber, cần kiểm tra lại
//        uriAttr.setValue("#" + signedTagId);
        uriAttr.setValue("");
        reference.setAttributeNode(uriAttr);
        signedInfo.appendChild(reference);
        Element transforms = doc.createElement("ds:Transforms");
        Element transform1 = doc.createElement("ds:Transform");
        Attr algoTransformAttr = doc.createAttribute("Algorithm");
        algoTransformAttr.setValue("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transform1.setAttributeNode(algoTransformAttr);
        transforms.appendChild(transform1);
        reference.appendChild(transforms);

//        if (namespacePrefix != null && !namespacePrefix.isEmpty()) {
//            Element transform2 = doc.createElement("ds:Transform");
//            Attr algoTransformAttr2 = doc.createAttribute("Algorithm");
//            algoTransformAttr2.setValue("http://www.w3.org/2001/10/xml-exc-c14n#");
//            transform2.setAttributeNode(algoTransformAttr2);
//            transforms.appendChild(transform2);
//        }
        Element digestMethod = doc.createElement("ds:DigestMethod");
        Attr digestAlgoAttr = doc.createAttribute("Algorithm");
        digestAlgoAttr.setValue("http://www.w3.org/2000/09/xmldsig#sha1");
//        digestAlgoAttr.setValue("http://www.w3.org/2001/04/xmlenc#sha256");
        digestMethod.setAttributeNode(digestAlgoAttr);
        reference.appendChild(digestMethod);
        //tính toán base64 cua digestValue
        Element digestValue = doc.createElement("ds:DigestValue");
        digestValue.setTextContent(getDigestForRemote());
        reference.appendChild(digestValue);
        signedInfo.appendChild(reference);
        sigElement.appendChild(signedInfo);

        //signatureValue node
        Element signatureValue = doc.createElement("ds:SignatureValue");
        signatureValue.setTextContent("tmp_signature_it_will_be_replaced_later");
        sigElement.appendChild(signatureValue);

        //keyInfo node
        Element keyInfo = doc.createElement("ds:KeyInfo");
        Element x509Data = doc.createElement("ds:X509Data");
        Element x509Certificate = doc.createElement("ds:X509Certificate");
        x509Certificate.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);
        sigElement.appendChild(keyInfo);

        //finish doc, cũng chả để làm gì
        doc.appendChild(sigElement);
        return sigElement;
    }

    public HashResponse performHash() throws Exception {
        //Chèn node signature tạo tạm vào file cần ký
        Element signature = prepareSignature();
        Element tmpNode = (Element) inputDoc.importNode(signature, true);
        inputDoc.getDocumentElement().insertBefore(tmpNode, null);

        //Lấy toàn bộ thẻ SignedInfo đã tạo tạm để ký
        Node signedInfo = signature.getElementsByTagName("ds:SignedInfo").item(0);
        //format lại định dạng dữ liệu xml theo chuẩn
        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(signedInfo);
        //hash
        byte[] hash = sha1(transformed);
        //lưu cache document đang xử lý theo sessionId, trả về hash và sessionId
        String sessionId = UUID.randomUUID().toString();
        //for test
//        new Wrapper().write(inputDoc, "/Users/chen/Desktop/tmp_" + sessionId + ".xml", false);
        Cache.getInstance().set(sessionId, inputDoc);
        return new HashResponse(sessionId, Base64.getEncoder().encodeToString(hash));
    }

    private byte[] sha1WithInfo(byte[] data) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGO, provider);
        messageDigest.update(data);
        byte[] digest = messageDigest.digest();
        DERObjectIdentifier sha1oid_ = new DERObjectIdentifier(HASH_ALGO_OID);

        AlgorithmIdentifier sha1aid_ = new AlgorithmIdentifier(sha1oid_, null);
        DigestInfo di = new DigestInfo(sha1aid_, digest);
        return di.getDEREncoded();
    }

    private byte[] sha1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
        md.update(data);
        return md.digest();
    }

    private String getDigestForRemote() throws Exception {
        Node nodeToBeHash = inputDoc.getElementsByTagName(signedTagId).item(0);

        //format lại định dạng dữ liệu xml theo chuẩn
        byte[] transformed = null;
        Canonicalizer c14n = null;
        //TODO: kiểm tra lại trường hợp có namespace prefix, tạm thời fix theo Cyber
//        if (namespacePrefix != null && !namespacePrefix.isEmpty()) {
//            //http://www.w3.org/2001/10/xml-exc-c14n#
//            c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//            transformed = c14n.canonicalizeSubtree(nodeToBeHash, namespacePrefix);
//        } else {
//            //http://www.w3.org/TR/2001/REC-xml-c14n-20010315
//            c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
//            transformed = c14n.canonicalizeSubtree(nodeToBeHash);
//        }
        //http://www.w3.org/TR/2001/REC-xml-c14n-20010315
        c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        transformed = c14n.canonicalizeSubtree(nodeToBeHash);

        //hash dữ liệu đã định dạng
        return Base64.getEncoder().encodeToString(sha1(transformed));
    }

    class HashResponse {
        private String hash;
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
