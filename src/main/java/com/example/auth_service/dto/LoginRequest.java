package com.example.auth_service.dto;

public class LoginRequest {
    private String username;
    private String password;

    // Getters y Setters manuales para asegurar que compile sin depender de Lombok
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}