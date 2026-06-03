package com.example.auth_service.repository;

import com.example.auth_service.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    // Spring genera la query automáticamente para buscar por el campo username o correo
    Optional<Usuario> findByUsername(String username);
}