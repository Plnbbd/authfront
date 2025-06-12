package cm.adcsa.auth.repository;

import cm.adcsa.auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByNom(String nom);

    boolean existsByNom(String nom);
}