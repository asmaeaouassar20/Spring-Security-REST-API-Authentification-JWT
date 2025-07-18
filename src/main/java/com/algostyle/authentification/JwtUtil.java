package com.algostyle.authentification;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

/**
 * Cete classe es utilitaire pour la gestion des JWT (JSON Web Tokens) dans une application Spring Boot
 */

@Component
public class JwtUtil {

    // Clé secrète utilisée pour signer les tokens (doit être modifié, car elle est codée ici en dur, ce n'est pas idéal pour la production)
    private String secret = "mySecretKeyThatIsLongEnoughForHS256Algorithm";
    private int jwtExpirationInMs = 86400000; // 24 heures => Durée de validité des tokens


    /**
     * Génération du token
     *  -> Créer un JWT avec le sujet username
     *  -> Date d'émission et d'expiration
     *  -> SIgné avec l'algorithme HS256
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }



    // Récupération du sujet
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /*****   Méthodes pour extraire des informations  ******/

    // Récupération de la date d'expiration
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    // Méthode générique pour extraire n'importe quelle claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    // Parser le token et retourne toutes les claims (càd analyser/décoder le jeton et retourner toutes les informations qu'il contient (les claims)
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }









    /********* Méthodes pour valider le token   **********/

    // Méthode validateToken qui prend un UserDetails en paramètre
    // Permet de valider le nom d'utilisateur et l'expiration
    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (SignatureException e) {
            System.err.println("Invalid JWT signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.err.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.err.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.err.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }



    // Méthode alternative qui valide seulement le token sans UserDetails
    // Vérifier seulement la signature et l'expiration
    public Boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (SignatureException e) {
            System.err.println("Invalid JWT signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.err.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.err.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.err.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }








    // Méthode pour vérifier si le token est valide pour un utilisateur spécifique


    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, String username) {
        try {
            return extractUsername(token).equals(username) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // Méthode pour obtenir le temps d'expiration restant en millisecondes
    public long getExpirationTime(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration.getTime() - System.currentTimeMillis();
        } catch (Exception e) {
            return 0;
        }
    }

    // Méthode pour vérifier si un token peut être rafraîchi
    public Boolean canTokenBeRefreshed(String token) {
        return !isTokenExpired(token);
    }

    // Méthode pour rafraîchir un token
    public String refreshToken(String token) {
        try {
            final String username = extractUsername(token);
            return generateToken(username);
        } catch (Exception e) {
            return null;
        }
    }
}