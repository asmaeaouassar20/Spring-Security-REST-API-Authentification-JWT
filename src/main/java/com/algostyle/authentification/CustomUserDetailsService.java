package com.algostyle.authentification;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.stereotype.Service;

import java.util.Optional;


/**
 * Cette classe est une implémentation personnalisée du service UserDetailsService de Spring Security,
 * utilisé pour charger les détails d'un utilisateur pendant le processus d'authentification
 */

@Service    // Marque que cette classe comme un service Spring qui sera géré par le conteneur IoC
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired  //Pour injecter automatiquement une instance de UserRepository
    private UserRepository userRepository;


    /**
     * Implémentation de l'interface UserDetailsService
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException("Utilisateur non trouvé : " + username);
        }

        /**
         * On récupère l'utilisateur trouvé, et on créé un builder pour construire un objet UserDetails
         */
        User foundUser = user.get();
        UserBuilder builder = org.springframework.security.core.userdetails.User.withUsername(foundUser.getUsername());
        builder.password(foundUser.getPassword());
        builder.authorities("USER"); // On peut ajouter des rôles ici

        return builder.build();
    }
}