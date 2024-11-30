package com.example.validadorfirmas.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignatureData {
    private String identificacion;
    private String nombre;
    private String apellido;
}