// SignatureResponse.java
package com.example.validadorfirmas.dto;

import lombok.Data;
import java.util.Date;

@Data
public class SignatureResponse {
    private String nombreCompleto;
    private String cedula;
    private String entidadCertificadora;
    private Date fechaFirma;
    private boolean esValida;
}