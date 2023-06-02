package com.example.demo.appuser;


import com.example.demo.registration.token.ConfirmationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Transactional(readOnly = true)
@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
    Optional<AppUser> getReferenceByEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE AppUser a SET a.enabled = TRUE WHERE a.email = ?1")
    void setEnabled(String email);
}
