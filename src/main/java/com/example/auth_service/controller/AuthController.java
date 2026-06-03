package com.example.auth_service.controller;

import com.google.firebase.auth.FirebaseAuth;
import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.model.Usuario;
import com.example.auth_service.repository.UsuarioRepository;
import com.example.auth_service.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<?> loginWithDatabaseAndFirebase(@RequestBody LoginRequest loginRequest) {
        try {
            // 1. Validar el usuario en tu base de datos MySQL local
            Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(loginRequest.getUsername());

            if (usuarioOpt.isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "El usuario no existe en MySQL");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }

            Usuario usuario = usuarioOpt.get();

            if (!usuario.getPassword().equals(loginRequest.getPassword())) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Contraseña incorrecta");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }

            // 2. MAGIA DE FIREBASE: Sincronizar o verificar con el servicio de Firebase
            String firebaseCustomToken = "";
            try {
                // Generamos un Custom Token de Firebase usando el Username de tu base de datos.
                // Esto te permite conectar el usuario de tu SQL con la base de datos en tiempo real de Firebase.
                firebaseCustomToken = FirebaseAuth.getInstance()
                        .createCustomToken(usuario.getUsername());
            } catch (Exception fe) {
                System.out.println("Aviso: Firebase no pudo generar el token secundario: " + fe.getMessage());
            }

            // 3. Generar tu JWT local firmado de Spring para la sesión de la página
            Map<String, Object> extraClaims = new HashMap<>();
            extraClaims.put("userId", usuario.getId());
            extraClaims.put("firebaseSync", !firebaseCustomToken.isEmpty());
            
            String tokenJwtLocal = jwtService.generateToken(usuario.getUsername(), extraClaims);

            // 4. Enviar todo de vuelta a tu PÁGINA web
            Map<String, String> response = new HashMap<>();
            response.put("token", tokenJwtLocal); // Tu JWT de Spring
            response.put("firebaseToken", firebaseCustomToken); // El token para Firebase frontend
            response.put("username", usuario.getUsername());
            
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Error en el servidor: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
}