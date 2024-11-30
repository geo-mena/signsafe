package com.example.validadorfirmas.service;

import com.example.validadorfirmas.dto.SignatureResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Slf4j
public class ValidadorService {

    public List<SignatureResponse> verificarFirmas(MultipartFile file) {
        List<SignatureResponse> firmas = new ArrayList<>();
        
        try (PDDocument document = PDDocument.load(file.getInputStream())) {
            List<PDSignature> signatures = document.getSignatureDictionaries();
            
            for (PDSignature signature : signatures) {
                try {
                    SignatureResponse firma = procesarFirma(signature, file);
                    if (firma != null) {
                        firmas.add(firma);
                    }
                } catch (Exception e) {
                    log.error("Error procesando firma: {}", e.getMessage());
                }
            }
            
        } catch (IOException e) {
            log.error("Error al cargar el documento PDF: {}", e.getMessage());
        }
        
        return firmas;
    }

    private SignatureResponse procesarFirma(PDSignature signature, MultipartFile file) throws Exception {
        byte[] contenidoFirma = signature.getContents(file.getInputStream());
        byte[] signedContent = signature.getSignedContent(file.getInputStream());
        
        CMSSignedData signedData = new CMSSignedData(contenidoFirma);
        Store<X509CertificateHolder> certificados = signedData.getCertificates();
        
        for (SignerInformation signerInfo : signedData.getSignerInfos()) {
            Collection<X509CertificateHolder> certCollection = certificados.getMatches(signerInfo.getSID());
            
            if (!certCollection.isEmpty()) {
                X509CertificateHolder certHolder = certCollection.iterator().next();
                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
                
                SignatureResponse firma = new SignatureResponse();
                firma.setNombreCompleto(extractNombre(cert));
                firma.setCedula(extractCedula(cert));
                firma.setEntidadCertificadora(cert.getIssuerX500Principal().getName());
                firma.setFechaFirma(signature.getSignDate().getTime());
                firma.setEsValida(verificarFirma(signerInfo, cert, signedContent));
                
                return firma;
            }
        }
        
        return null;
    }

    private String extractNombre(X509Certificate cert) {
        String subjectDN = cert.getSubjectX500Principal().getName();
        // Extraer CN del DN
        String cn = extractDNField(subjectDN, "CN=");
        return cn != null ? cn : "No disponible";
    }

    private String extractCedula(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue("1.3.6.1.4.1.3.101.1.10");
            if (extensionValue != null) {
                String value = new String(extensionValue);
                // Buscar patrón de cédula ecuatoriana (10 dígitos)
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\b\\d{10}\\b");
                java.util.regex.Matcher matcher = pattern.matcher(value);
                if (matcher.find()) {
                    return matcher.group();
                }
            }
        } catch (Exception e) {
            log.error("Error extrayendo cédula: {}", e.getMessage());
        }
        return "No disponible";
    }

    private boolean verificarFirma(SignerInformation signerInfo, X509Certificate cert, byte[] signedContent) {
        try {
            return signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
        } catch (Exception e) {
            log.error("Error verificando firma: {}", e.getMessage());
            return false;
        }
    }

    private String extractDNField(String dn, String field) {
        int start = dn.indexOf(field);
        if (start >= 0) {
            start += field.length();
            int end = dn.indexOf(',', start);
            if (end < 0) end = dn.length();
            return dn.substring(start, end).trim();
        }
        return null;
    }
}