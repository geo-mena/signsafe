package com.example.validadorfirmas.controllers;

import com.example.validadorfirmas.dto.ApiResponse;
import com.example.validadorfirmas.dto.SignatureResponse;
import com.example.validadorfirmas.service.ValidadorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/validador")
@RequiredArgsConstructor
public class ValidadorController {

    private final ValidadorService validadorService;

    @PostMapping("/verificar")
    public ResponseEntity<ApiResponse<List<SignatureResponse>>> verificarDocumento(
            @RequestParam("file") MultipartFile file) {
        List<SignatureResponse> firmas = validadorService.verificarFirmas(file);
        
        if (firmas.isEmpty()) {
            return ResponseEntity.ok(new ApiResponse<>(
                false, 
                "No se encontraron firmas digitales en el documento", 
                firmas
            ));
        }

        return ResponseEntity.ok(new ApiResponse<>(
            true,
            "Se encontraron " + firmas.size() + " firma(s) en el documento",
            firmas
        ));
    }
}