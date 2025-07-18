package com.algostyle.authentification;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * Cette classe permet de faire une configuration Spring Security qui définit la stratégie de sécurité pourune application utilisant JWT
 */


// Activer la sécurité web
@Configuration
@EnableWebSecurity



public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;





    // Définir la chaîne de filtres de sécurité
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable() // Désactiver CSRF (Cross-Site request Forgery) car inutile avec JWT
                .cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)     // Rendre l'app sans état (stateless), nécessaire pour une API REST avec JWT
                .and()

                // Permettre un accès libre au signup et login
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/auth/signup", "/api/auth/login").permitAll()
                        .anyRequest().authenticated()   // Toutes les autres requêtes nécessitent une authentification
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // Ajouter le filtre JWT avant le filtre d'authentification standard de Spring

        return http.build();
    }




    /* ****** Beans utilitaires  ****** */



    // - utiliser BCryptPasswordEncoder, l'encodeur de mot de passe recommandé par Spring Security
    // - Fournir un hachage sécurisé avec salage intégré  ( le salage (salt) c'est une valeur aléatoire ajoutée au mdp avant de le hacher, cela emp^che deux mdp identiques d'avoir le même résultat de hachage -  Ajouter automatiquement un élément aléatoire (le sel) pour plus de sécurité.)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * -> Récupérer le gestionnaire d'authentification par défaut de Spring
     * -> Nécessaire pour le processus d'authentification
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}