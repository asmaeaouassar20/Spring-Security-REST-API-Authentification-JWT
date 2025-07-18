package com.algostyle.authentification;



import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;


/**
 * Cette classe implémente un filtre d'authentification JWT (JSON Web Token) pour une application Spring Boot
 */

@Component // Pour être gérée par Spring

// Cette classe étend "OncePerRequestFilter", ce qui garantit qu'elle s'exécute une fois par requête HTTP
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    // Injection des dépendances
    @Autowired
    private JwtUtil jwtUtil;   // Pour manipuler les JWT (extraction d'information, validation)

    @Autowired
    private UserDetailsService userDetailsService;  // C'est un service Spring Security pour charger les détails de l'utilisateur

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        /* ****** étape 1 : Extraction du token JWT  ****** */
        // Récupérer le header "Authorization" de la requête
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // Vérifier si le header Authorization contient un token Bearer
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);    // Extraire le token (en enlevant "Bearer")
            try {
                username = jwtUtil.extractUsername(jwt); // Extraire le nom d'utilisateur du token via JwtUtil
            } catch (Exception e) {
                logger.error("Erreur lors de l'extraction du nom d'utilisateur du token JWT", e);
            }
        }

        /* ****** étape 2 : Validation et authentification  ****** */
        // SI un nom d'utilisateur est trouvé et qu'il n'y a pas d'authentification existante dans le contexte de sécurité
        // Valider le token et configurer le SecurityContext
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Charger les détails de l'utilisateur via UserDetailsService
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Valider le token JWT avec l'utilisateur chargé
            if (jwtUtil.validateToken(jwt, userDetails)) {

                // Créer un objet d'authentification Spring Security
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Ajouter les détails de la requête web
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //Définir cette authentification dans le SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);  // Pour continuer l'exécution de la chaîne de filtres
    }
}