package org.saeta.serviciovalidadorfirma.service;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.security.cert.*;
import java.util.*;

@Service
public class SignatureService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ResponseEntity<Map<String, Object>> validateSignature(MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        try {
            byte[] pdfBytes = file.getBytes();

            PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes));
            List<PDSignature> signatures = document.getSignatureDictionaries();

            if (signatures.isEmpty()) {
                response.put("isValid", false);
                response.put("message", "El documento PDF no contiene firmas digitales.");
                response.put("fileType", "PDF");
                return ResponseEntity.ok(response);
            }

            boolean allSignaturesValid = true;
            List<Map<String, Object>> signatureInfos = new ArrayList<>();

            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            // Fijar la zona horaria a Lima (-05:00, sin DST)
            dateFormat.setTimeZone(TimeZone.getTimeZone("America/Lima"));

            for (PDSignature signature : signatures) {
                Map<String, Object> signatureInfo = new HashMap<>();

                String name = signature.getName();
                String subFilter = signature.getSubFilter();
                String signatureType = getSignatureType(subFilter);

                signatureInfo.put("subFilter", subFilter != null ? subFilter : "Desconocido");
                signatureInfo.put("signatureType", signatureType);

                // Formatear la fecha de la firma
                Date signDate = signature.getSignDate().getTime();
                String formattedSignDate = dateFormat.format(signDate);
                signatureInfo.put("signDate", formattedSignDate);

                byte[] contents = signature.getContents(pdfBytes);
                byte[] signedContent = signature.getSignedContent(pdfBytes);

                CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), contents);

                // Obtener los certificados del firmante
                Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
                SignerInformationStore signers = signedData.getSignerInfos();
                Collection<SignerInformation> signerInfos = signers.getSigners();

                boolean signatureValid = true;

                for (SignerInformation signerInfo : signerInfos) {
                    Collection<X509CertificateHolder> certCollection = certificatesStore.getMatches(signerInfo.getSID());

                    List<X509Certificate> certList = new ArrayList<>();
                    JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");
                    for (X509CertificateHolder certHolder : certCollection) {
                        X509Certificate cert = certConverter.getCertificate(certHolder);
                        certList.add(cert);
                    }

                    if (certList.isEmpty()) {
                        allSignaturesValid = false;
                        signatureValid = false;
                        signatureInfo.put("valid", false);
                        signatureInfo.put("reason", "No se encontraron certificados en la firma.");
                        continue;
                    }

                    X509Certificate signerCert = certList.get(0);

                    // Verificar la firma criptográfica
                    SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC")
                            .build(signerCert);

                    if (!signerInfo.verify(verifier)) {
                        allSignaturesValid = false;
                        signatureValid = false;
                        signatureInfo.put("valid", false);
                        signatureInfo.put("reason", "La verificación criptográfica de la firma falló.");
                        continue;
                    }

                    signatureInfo.put("valid", true);
                    signatureInfo.put("signerName", signerCert.getSubjectDN().toString());
                    signatureInfo.put("issuerName", signerCert.getIssuerDN().toString());
                    signatureInfo.put("serialNumber", signerCert.getSerialNumber().toString(16));

                    // Obtener el algoritmo de hash
                    String hashAlgorithm = getHashAlgorithm(signerInfo.getDigestAlgorithmID());
                    signatureInfo.put("hashAlgorithm", hashAlgorithm);

                    // Determinar el nivel de la firma
                    String signatureLevel = determineSignatureLevel(signerInfo, signatureType);
                    signatureInfo.put("signatureLevel", signatureLevel);

                    // Si el nombre es nulo o vacío, obtener el CN del certificado
                    if (name == null || name.trim().isEmpty()) {
                        name = getCommonName(signerCert);
                    }
                }

                signatureInfo.put("name", name != null ? name : "Desconocido");
                signatureInfos.add(signatureInfo);
            }

            response.put("isValid", allSignaturesValid);
            response.put("fileType", "PDF");
            response.put("signatures", signatureInfos);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", "Error al validar la firma: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    private String getSignatureType(String subFilter) {
        if (subFilter == null) {
            return "Desconocido";
        }
        switch (subFilter) {
            case "adbe.x509.rsa_sha1":
                return "PKCS#1";
            case "adbe.pkcs7.detached":
                return "PKCS#7 Detached";
            case "adbe.pkcs7.sha1":
                return "PKCS#7 SHA1";
            case "ETSI.CAdES.detached":
                return "PAdES (CAdES Detached)";
            case "ETSI.RFC3161":
                return "Timestamp";
            default:
                return "Desconocido";
        }
    }

    private String getHashAlgorithm(AlgorithmIdentifier digestAlgorithmId) {
        ASN1ObjectIdentifier oid = digestAlgorithmId.getAlgorithm();
        String algorithmName = oid.getId();

        switch (algorithmName) {
            case "1.3.14.3.2.26":
                return "SHA-1";
            case "2.16.840.1.101.3.4.2.1":
                return "SHA-256";
            case "2.16.840.1.101.3.4.2.2":
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":
                return "SHA-512";
            default:
                return "Desconocido";
        }
    }

    private String determineSignatureLevel(SignerInformation signerInfo, String signatureType) {
        // Analizar los atributos para determinar el nivel de la firma
        boolean hasTimeStamp = false;
        boolean hasValidationData = false;

        // Verificar atributos no firmados
        AttributeTable unsignedAttributes = signerInfo.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            // OID para id-aa-signatureTimeStampToken
            ASN1ObjectIdentifier timeStampTokenOID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");
            if (unsignedAttributes.get(timeStampTokenOID) != null) {
                hasTimeStamp = true;
            }

            // OID para atributos de datos de validación (ejemplo)
            ASN1ObjectIdentifier completeCertificateRefsOID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.21");
            ASN1ObjectIdentifier completeRevocationRefsOID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.22");

            if (unsignedAttributes.get(completeCertificateRefsOID) != null || unsignedAttributes.get(completeRevocationRefsOID) != null) {
                hasValidationData = true;
            }
        }

        if (signatureType.startsWith("PAdES")) {
            if (hasTimeStamp && hasValidationData) {
                return "PAdES-BASELINE-LT";
            } else if (hasTimeStamp) {
                return "PAdES-BASELINE-T";
            } else {
                return "PAdES-BASELINE-B";
            }
        } else if (signatureType.startsWith("PKCS#7")) {
            if (hasTimeStamp && hasValidationData) {
                return "PKCS7-LT";
            } else if (hasTimeStamp) {
                return "PKCS7-T";
            } else {
                return "PKCS7-B";
            }
        } else {
            return "Desconocido";
        }
    }

    private String getCommonName(X509Certificate certificate) {
        try {
            X500Name x500name = new X509CertificateHolder(certificate.getEncoded()).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return cn.getFirst().getValue().toString();
        } catch (Exception e) {
            return null;
        }
    }
}