package com.example.validadorfirmas.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    
    @GetMapping("/")
    public String home() {
        return "Bienvenido al servicio de validación de firmas digitales";
    }

    @GetMapping("/health")
    public String health() {
        return "El servicio está funcionando correctamente";
    }
}