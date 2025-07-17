package com.algostyle.authentification;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username déjà pris");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("Utilisateur créé avec succès");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser.isPresent() &&
                passwordEncoder.matches(user.getPassword(), existingUser.get().getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername());
            return ResponseEntity.ok(new JwtResponse(token));
        }
        return ResponseEntity.badRequest().body("Identifiants invalides");
    }

    @GetMapping("/me")
    public ResponseEntity<?> currentUserName(Authentication authentication) {
        // Vérifier si l'authentication est null
        if (authentication == null) {
            return ResponseEntity.badRequest().body("Utilisateur non authentifié");
        }

        try {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return ResponseEntity.ok("Nom d'utilisateur: " + userDetails.getUsername());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Erreur lors de la récupération des informations utilisateur");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        // Avec JWT, le logout est généralement géré côté client
        // Le client doit simplement supprimer le token de son stockage
        return ResponseEntity.ok("Déconnexion réussie");
    }

    // Classe interne pour la réponse JWT
    public static class JwtResponse {
        private String token;

        public JwtResponse(String token) {
            this.token = token;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }
}
