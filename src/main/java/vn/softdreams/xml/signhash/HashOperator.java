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
    //xml chưa ký
    private Document inputDoc;
    //Thông tin chứng thư số
    private X509Certificate cert;
    //Thông tin định dạng file xml đầu vào
    //Id của signature sau khi ký
    private String signatureTagId;
    //Thông tin của tag dữ liệu cần ký
    private String signingTagId;
    private String signingTagName;
    //Namespace của file cần ký, inv:invoiceData -> namespace = inv
    private String namespacePrefix;
    private boolean usingNS;
    //Hash algo, default SHA1
    private DigestAlgorithm hashAlgo;
    //Thẻ cha của thẻ signature cần thêm vào
    private Node sigParentNode;

    public HashOperator(Document inputDoc, X509Certificate cert, String signingTagId,
                        String signingTagName, String namespacePrefix) {
        this.inputDoc = inputDoc;
        this.cert = cert;
        this.signingTagId = signingTagId;
        this.signingTagName = signingTagName;
        this.namespacePrefix = namespacePrefix;
        this.usingNS = !namespacePrefix.isEmpty();
        hashAlgo = DigestAlgorithm.SHA1;
        Init.init();
    }

    //Kiểm tra thẻ cần ký hợp lệ hay chưa, và tìm parent để add thẻ signature vào cùng level với thẻ cần ký
    private void checkValidDoc() throws Exception {
        if (inputDoc == null) throw new Exception("Document is null");
        if (signingTagId == null || signatureTagId.isEmpty()) throw new Exception("SigningTagId must be defined");
        NodeList nl = inputDoc.getElementsByTagName(signingTagName);
        if (nl.getLength() == 0) throw new Exception("Xml tag with name = " + signingTagName + " not exist");
        if (nl.getLength() > 1) throw new Exception("More than 1 xml tag with name = " + signingTagName);
        Node processingNode = nl.item(0);
        if (!processingNode.getAttributes().getNamedItem("ID").getTextContent().equals(signingTagId))
            throw new Exception("SigningTagName and SigningTagId are not valid");
        sigParentNode = processingNode.getParentNode();
    }

    public void setSignatureTagId(String signatureTagId) {
        this.signatureTagId = signatureTagId;
    }

    public void setHashAlgo(DigestAlgorithm hashAlgo) {
        this.hashAlgo = hashAlgo;
    }

    private Element prepareSignature() throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        //root signature node
        Element sigElement = doc.createElement("Signature");
        if (signatureTagId != null && !signatureTagId.isEmpty()) {
            sigElement.setAttribute("Id", signatureTagId);
        }
        sigElement.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

        //signedInfo node
        Element signedInfo = doc.createElement("SignedInfo");
        //signedInfo-canonicalizationMethod node
        Element canonicalizationMethod = doc.createElement("CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", usingNS ? "http://www.w3.org/2001/10/xml-exc-c14n#" : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        signedInfo.appendChild(canonicalizationMethod);
        //signedInfo-SignatureMethod node
        Element signatureMethod = doc.createElement("SignatureMethod");
        signatureMethod.setAttribute("Algorithm", hashAlgo.getSignatureMethod());
        signedInfo.appendChild(signatureMethod);

        //SignedInfo-Reference node
        Element reference = doc.createElement("Reference");
        reference.setAttribute("URI", "#" + signingTagId);
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
        //tính toán base64 cua digestValue
        Element digestValue = doc.createElement("DigestValue");
        digestValue.setTextContent(getDigestForRemote());
        reference.appendChild(digestValue);
        signedInfo.appendChild(reference);
        sigElement.appendChild(signedInfo);

        //signatureValue node
        Element signatureValue = doc.createElement("SignatureValue");
//        signatureValue.setTextContent("");
        sigElement.appendChild(signatureValue);

        //keyInfo node
        Element keyInfo = doc.createElement("KeyInfo");
        Element x509Data = doc.createElement("X509Data");
        Element x509Certificate = doc.createElement("X509Certificate");
        x509Certificate.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);
        sigElement.appendChild(keyInfo);

        //finish doc, cũng chả để làm gì
        doc.appendChild(sigElement);
        return sigElement;
    }

    public HashResponse performHash() throws Exception {
        checkValidDoc();
        //Chèn node signature tạo tạm vào file cần ký
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        Element signature = prepareSignature();
        Element tmpNode = (Element) inputDoc.importNode(signature, true);
        sigParentNode.appendChild(tmpNode);

        //Lấy toàn bộ thẻ SignedInfo đã tạo tạm để ký, đưa vào 1 document, và tạo attr xmlns (bắt buộc)
        Node signedInfo = signature.getElementsByTagName("SignedInfo").item(0);
        Element signedInfoEle = (Element) doc.importNode((Element) signedInfo, true);
        signedInfoEle.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        doc.appendChild(signedInfoEle);

        //format lại định dạng dữ liệu xml theo chuẩn
        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(doc);
        //hash
        byte[] hash = DigestCreator.digestWithInfo(transformed, hashAlgo);
        //lưu cache document đang xử lý theo sessionId, trả về hash và sessionId
        String sessionId = UUID.randomUUID().toString();
        Cache.getInstance().set(sessionId, inputDoc);
        return new HashResponse(sessionId, Base64.getEncoder().encodeToString(hash));
    }

    private String getDigestForRemote() throws Exception {
        Node nodeToBeHash = inputDoc.getElementsByTagName(signingTagName).item(0);

        //format lại định dạng dữ liệu xml theo chuẩn
        Canonicalizer c14n = usingNS ?
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS) : Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(nodeToBeHash);

        //hash dữ liệu đã định dạng
        return Base64.getEncoder().encodeToString(DigestCreator.digest(transformed, hashAlgo));
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
