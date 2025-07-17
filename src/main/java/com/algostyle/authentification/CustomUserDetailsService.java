package com.algostyle.authentification;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException("Utilisateur non trouvé : " + username);
        }

        User foundUser = user.get();
        UserBuilder builder = org.springframework.security.core.userdetails.User.withUsername(foundUser.getUsername());
        builder.password(foundUser.getPassword());
        builder.authorities("USER"); // Vous pouvez ajouter des rôles ici

        return builder.build();
    }
}