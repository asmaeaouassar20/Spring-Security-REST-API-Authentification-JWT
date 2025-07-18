package com.algostyle.authentification;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")    // Base path pour les endpoints d'authentification
@CrossOrigin(origins = "http://localhost:4200")     // Autorise les requêtes depuis le front Angular
public class AuthController {

    @Autowired
    private UserRepository userRepository;  // Pour l'accès à la base de données des utilisateurs

    @Autowired
    private PasswordEncoder passwordEncoder;    // Service de hachage des mots de passe

    @Autowired
    private JwtUtil jwtUtil;    // Pour la génération et la vérification de JWT


    /**
     * Inscription d'un nouvel utilisateur
     * Vérifier si le nom d'utilisateur est déjà pris avant de créer le compte
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username déjà pris");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));   // Hacher le mot de passe
        userRepository.save(user);  // Sauvegarder l'utilisateur en base
        return ResponseEntity.ok("Utilisateur créé avec succès");
    }


    /**
     * Connexion d'un utilisateur
     * Vérifier les identifiants et retourne un JWT si valide
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser.isPresent() &&
                passwordEncoder.matches(user.getPassword(), existingUser.get().getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername()); // Générer un token JWT
            return ResponseEntity.ok(new JwtResponse(token));
        }
        return ResponseEntity.badRequest().body("Identifiants invalides");
    }


    /**
     * Récupérer les informations de l'utilisateur actuellement connecté
     */
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


    /**
     * Déconnexion (gérée côté client avec supression du token)
     * @return
     */
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
