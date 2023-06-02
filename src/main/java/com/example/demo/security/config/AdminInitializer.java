package com.example.demo.security.config;

import com.example.demo.appuser.AppUser;
import com.example.demo.appuser.AppUserRepository;
import com.example.demo.appuser.AppUserRole;
import lombok.AllArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Component
public class AdminInitializer implements CommandLineRunner {
    AppUserRepository userRepository;
    BCryptPasswordEncoder passwordEncoder;

    @Override
    public void run(String...args) throws Exception {
        AppUser admin = new AppUser("admin", "admin", "admin", passwordEncoder.encode("admin"), AppUserRole.ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);
    }
}
