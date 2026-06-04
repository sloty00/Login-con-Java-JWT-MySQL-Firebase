package com.example.auth_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        // 1. Extraer el encabezado de autorización
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // 2. Si no viene el token o no empieza con "Bearer ", ignoramos y seguimos el flujo
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Cortar el string para sacar solo el token JWT puro
        jwt = authHeader.substring(7);
        try {
            username = jwtService.extractUsername(jwt);

            // 4. Si el token tiene usuario y no está autenticado ya en la sesión actual
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                
                // Validamos si el token es legítimo para ese usuario
                if (jwtService.isTokenValid(jwt, username)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            new ArrayList<>() // Aquí irían los roles si los tuvieras
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    
                    // Autorizamos al usuario dentro del contexto de seguridad de Spring
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            System.out.println("Error al procesar el JWT Filtro: " + e.getMessage());
        }

        // Continuar con los siguientes filtros
        filterChain.doFilter(request, response);
    }
}