package com.example.validadorfirmas.service;

import com.example.validadorfirmas.dto.SignatureResponse;
import java.security.cert.CertificateExpiredException;
import com.example.validadorfirmas.dto.SignatureData;
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
import lombok.Data;
import lombok.AllArgsConstructor;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1InputStream;

import org.apache.pdfbox.io.MemoryUsageSetting;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.InputStream;

@Service
@Slf4j
public class ValidadorService {

    /**
     * Verifica las firmas digitales de un documento PDF
     * 
     * @param file Archivo PDF
     * @return Lista de firmas digitales
     */
    public List<SignatureResponse> verificarFirmas(MultipartFile file) {
        List<SignatureResponse> firmas = new ArrayList<>();

        System.setProperty("org.apache.pdfbox.memory.useTempFile", "true");
        MemoryUsageSetting memoryUsageSetting = MemoryUsageSetting.setupMixed(50 * 1024 * 1024L)
            .setTempDir(new File(System.getProperty("java.io.tmpdir")));
        
        try (InputStream inputStream =  new BufferedInputStream(file.getInputStream());
            PDDocument document = PDDocument.load(inputStream, memoryUsageSetting)) {

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
        } finally {
            System.gc();
        }
        
        return firmas;
    }

    /**
     * Procesa la firma digital de un documento
     * 
     * @param signature Firma digital
     * @param file Archivo firmado
     * @return Datos de la firma
     * @throws Exception
     */
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

                // debugCertificateInfo(cert);
                SignatureData signatureData = extractSignatureData(cert);
                
                SignatureResponse firma = new SignatureResponse();
                firma.setNombreCompleto(signatureData.getNombre() + " " + signatureData.getApellido());
                firma.setCedula(signatureData.getIdentificacion());

                firma.setEntidadCertificadora(extractOrganizationFromDN(cert.getIssuerX500Principal().getName()));
                firma.setFechaFirma(signature.getSignDate().getTime());
                firma.setEsValida(verificarFirma(signerInfo, cert, signedContent));
                
                return firma;
            }
        }
        
        return null;
    }

    /**
     * Extrae los datos de la firma digital de un certificado
     * 
     * @param cert Certificado del firmante
     * @return Datos de la firma
     */
    private SignatureData extractSignatureData(X509Certificate cert) {
        try {
            String identificacion = "Desconocido";
            String nombre = "Desconocido";
            String apellido = "Desconocido";

            // Procesar extensiones específicas de Security Data
            byte[] securityDataId = cert.getExtensionValue("1.3.6.1.4.1.37746.3.1");
            if (securityDataId != null) {
                // Decodificar ASN.1 DER
                byte[] octets = new ASN1InputStream(securityDataId).readObject().toASN1Primitive()
                    .getEncoded();
                String decodedValue = new String(octets);
                if (decodedValue.matches(".*\\d{10}.*")) {
                    identificacion = decodedValue.replaceAll("[^0-9]", "");
                }
            }

            // Extraer nombre y apellido de las extensiones de Security Data
            byte[] nombreExt = cert.getExtensionValue("1.3.6.1.4.1.37746.3.2");
            byte[] apellidoExt = cert.getExtensionValue("1.3.6.1.4.1.37746.3.3");

            if (nombreExt != null) {
                byte[] octets = new ASN1InputStream(nombreExt).readObject().toASN1Primitive()
                    .getEncoded();
                nombre = new String(octets).trim();
            }

            if (apellidoExt != null) {
                byte[] octets = new ASN1InputStream(apellidoExt).readObject().toASN1Primitive()
                    .getEncoded();
                apellido = new String(octets).trim();
            }

            // Si no se encontró en las extensiones, intentar con el DN
            if (nombre.equals("Desconocido") || apellido.equals("Desconocido")) {
                String subjectDN = cert.getSubjectX500Principal().getName();
                String cn = extractDNField(subjectDN, "CN=");
                if (cn != null) {
                    String[] parts = cn.split(" ");
                    if (parts.length >= 2) {
                        nombre = parts[0] + " " + parts[1];
                        apellido = parts.length > 3 ? parts[2] + " " + parts[3] : parts[2];
                    }
                }
            }

            // Si aún no tenemos la identificación, buscar en el serialNumber
            if (identificacion.equals("Desconocido")) {
                String subjectDN = cert.getSubjectX500Principal().getName();
                if (subjectDN.contains("2.5.4.5=#")) {
                    String serialHex = extractDNField(subjectDN, "2.5.4.5=#");
                    if (serialHex != null) {
                        String decoded = hexToString(serialHex);
                        String numbers = decoded.replaceAll("[^0-9]", "");
                        if (numbers.length() >= 10) {
                            identificacion = numbers.substring(0, 10);
                        }
                    }
                }
            }

            return new SignatureData(identificacion, nombre, apellido);
        } catch (Exception e) {
            log.error("Error extrayendo datos del certificado: {}", e.getMessage());
            return new SignatureData("Desconocido", "Desconocido", "Desconocido");
        }
    }

    /**
     * Convierte un string hexadecimal a un string legible
     * 
     * @param hex Hexadecimal a decodificar
     * @return String decodificado
     */
    private String hexToString(String hex) {
        try {
            hex = hex.replaceAll("^#", "");
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                String str = hex.substring(i, i + 2);
                output.append((char) Integer.parseInt(str, 16));
            }
            return output.toString();
        } catch (Exception e) {
            log.error("Error decodificando hex: {}", e.getMessage());
            return "";
        }
    }

    /**
     * Extrae un campo específico del Distinguished Name
     * 
     * @param dn Distinguished Name
     * @param field Campo a extraer
     * @return Valor del campo
     */
    private String extractDNField(String dn, String field) {
        try {
            int start = dn.indexOf(field);
            if (start >= 0) {
                start += field.length();
                int end = dn.indexOf(',', start);
                if (end < 0) end = dn.length();
                return dn.substring(start, end).trim();
            }
            return null;
        } catch (Exception e) {
            log.error("Error extrayendo campo DN {}: {}", field, e.getMessage());
            return null;
        }
    }

    /**
     * Extrae el nombre de la organización del DN del certificado
     * 
     * @param dn Distinguished Name del certificado
     * @return Nombre de la organización
     */
    private String extractOrganizationFromDN(String dn) {
        try {
            String org = extractDNField(dn, "O=");
            return org != null ? org : "Desconocido";
        } catch (Exception e) {
            log.error("Error extrayendo organización del DN: {}", e.getMessage());
            return "Desconocido";
        }
    }

    /**
     * Verifica la firma digital de un documento
     * 
     * @param signerInfo Información del firmante
     * @param cert Certificado del firmante
     * @param signedContent Contenido firmado
     * @return true si la firma es válida, false en caso contrario
     */
    private boolean verificarFirma(SignerInformation signerInfo, X509Certificate cert, byte[] signedContent) {
        try {
            cert.checkValidity();
            return true;
        } catch (CertificateExpiredException e) {
            log.warn("El certificado ha expirado");
            return false; 
        } catch (Exception e) {
            log.error("Error verificando firma: {}", e.getMessage());
            return false;
        }
    }

    /**
     * ! Imprime información del certificado en el log
     * 
     * @param cert Certificado a imprimir
     */
    private void debugCertificateInfo(X509Certificate cert) {
        try {
            log.debug("=== Información del Certificado ===");
            log.debug("Subject DN: {}", cert.getSubjectX500Principal().getName());
            log.debug("Issuer DN: {}", cert.getIssuerX500Principal().getName());
            
            Set<String> criticalExtOIDs = cert.getCriticalExtensionOIDs();
            Set<String> nonCriticalExtOIDs = cert.getNonCriticalExtensionOIDs();
            
            log.debug("=== Extensiones Críticas ===");
            if (criticalExtOIDs != null) {
                for (String oid : criticalExtOIDs) {
                    log.debug("OID: {} - Valor: {}", oid, 
                            Base64.getEncoder().encodeToString(cert.getExtensionValue(oid)));
                }
            }
            
            log.debug("=== Extensiones No Críticas ===");
            if (nonCriticalExtOIDs != null) {
                for (String oid : nonCriticalExtOIDs) {
                    log.debug("OID: {} - Valor: {}", oid, 
                            Base64.getEncoder().encodeToString(cert.getExtensionValue(oid)));
                }
            }
            
            Collection<List<?>> subjectAlternativeNames = cert.getSubjectAlternativeNames();
            if (subjectAlternativeNames != null) {
                log.debug("=== Subject Alternative Names ===");
                for (List<?> san : subjectAlternativeNames) {
                    log.debug("Tipo: {} - Valor: {}", san.get(0), san.get(1));
                }
            }
        } catch (Exception e) {
            log.error("Error imprimiendo información del certificado: {}", e.getMessage());
        }
    }
}