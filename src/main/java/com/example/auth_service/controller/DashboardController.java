package com.example.auth_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    // Este recurso está protegido. Si entras directo desde el navegador te dará error 403 Forbidden
    @GetMapping("/datos-privados")
    public ResponseEntity<?> getDatosPrivados() {
        Map<String, String> data = new HashMap<>();
        data.put("mensaje", "¡Bienvenido, José! Estos datos vienen directo de la base de datos segura gracias a tu JWT.");
        data.put("estado", "Acceso Concedido de José");
        return ResponseEntity.ok(data);
    }
}