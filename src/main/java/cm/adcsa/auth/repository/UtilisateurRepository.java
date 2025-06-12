package cm.adcsa.auth.repository;

import cm.adcsa.auth.entity.StatutUtilisateur;
import cm.adcsa.auth.entity.Utilisateur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UtilisateurRepository extends JpaRepository<Utilisateur, Long> {

    Optional<Utilisateur> findByEmail(String email);

    Optional<Utilisateur> findByEmailAndStatut(String email, StatutUtilisateur statut);

    Optional<Utilisateur> findByTokenResetPassword(String token);

    boolean existsByEmail(String email);

    List<Utilisateur> findByStatut(StatutUtilisateur statut);

    @Query("SELECT u FROM Utilisateur u WHERE u.derniereConnexion < :date")
    List<Utilisateur> findUtilisateursInactifs(@Param("date") LocalDateTime date);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.tentativesConnexion = :tentatives WHERE u.id = :id")
    void updateTentativesConnexion(@Param("id") Long id, @Param("tentatives") Integer tentatives);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.dateVerrouillage = :dateVerrouillage WHERE u.id = :id")
    void updateDateVerrouillage(@Param("id") Long id, @Param("dateVerrouillage") LocalDateTime dateVerrouillage);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.derniereConnexion = :date WHERE u.id = :id")
    void updateDerniereConnexion(@Param("id") Long id, @Param("date") LocalDateTime date);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.motDePasse = :motDePasse WHERE u.id = :id")
    void updateMotDePasse(@Param("id") Long id, @Param("motDePasse") String motDePasse);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.tokenResetPassword = :token, u.dateExpirationToken = :dateExpiration WHERE u.id = :id")
    void updateTokenResetPassword(@Param("id") Long id, @Param("token") String token, @Param("dateExpiration") LocalDateTime dateExpiration);

    @Modifying
    @Query("UPDATE Utilisateur u SET u.tokenResetPassword = null, u.dateExpirationToken = null WHERE u.id = :id")
    void clearTokenResetPassword(@Param("id") Long id);

    @Query("SELECT COUNT(u) FROM Utilisateur u WHERE u.derniereConnexion >= :date")
    Long countUtilisateursConnectesDepuis(@Param("date") LocalDateTime date);

    @Query("SELECT u FROM Utilisateur u JOIN u.roles r WHERE r.nom = :roleName")
    List<Utilisateur> findByRoleName(@Param("roleName") String roleName);
}