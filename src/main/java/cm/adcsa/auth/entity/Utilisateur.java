package cm.adcsa.auth.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "utilisateur")
public class Utilisateur {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "nom", nullable = false, length = 100)
    private String nom;

    @Column(name = "prenom", nullable = false, length = 100)
    private String prenom;

    @Column(name = "email", nullable = false, unique = true, length = 150)
    private String email;

    @Column(name = "mot_de_passe", nullable = false)
    private String motDePasse;

    @Enumerated(EnumType.STRING)
    @Column(name = "statut", nullable = false)
    private StatutUtilisateur statut = StatutUtilisateur.ACTIF;

    @Column(name = "derniere_connexion")
    private LocalDateTime derniereConnexion;

    @Column(name = "date_creation", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime dateCreation;

    @Column(name = "date_modification")
    @UpdateTimestamp
    private LocalDateTime dateModification;

    @Column(name = "tentatives_connexion")
    private Integer tentativesConnexion = 0;

    @Column(name = "date_verrouillage")
    private LocalDateTime dateVerrouillage;

    @Column(name = "token_reset_password")
    private String tokenResetPassword;

    @Column(name = "date_expiration_token")
    private LocalDateTime dateExpirationToken;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "utilisateur_role",
        joinColumns = @JoinColumn(name = "utilisateur_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    // Constructeurs
    public Utilisateur() {}

    public Utilisateur(String nom, String prenom, String email, String motDePasse) {
        this.nom = nom;
        this.prenom = prenom;
        this.email = email;
        this.motDePasse = motDePasse;
    }

    // Getters et Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNom() {
        return nom;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public String getPrenom() {
        return prenom;
    }

    public void setPrenom(String prenom) {
        this.prenom = prenom;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMotDePasse() {
        return motDePasse;
    }

    public void setMotDePasse(String motDePasse) {
        this.motDePasse = motDePasse;
    }

    public StatutUtilisateur getStatut() {
        return statut;
    }

    public void setStatut(StatutUtilisateur statut) {
        this.statut = statut;
    }

    public LocalDateTime getDerniereConnexion() {
        return derniereConnexion;
    }

    public void setDerniereConnexion(LocalDateTime derniereConnexion) {
        this.derniereConnexion = derniereConnexion;
    }

    public LocalDateTime getDateCreation() {
        return dateCreation;
    }

    public void setDateCreation(LocalDateTime dateCreation) {
        this.dateCreation = dateCreation;
    }

    public LocalDateTime getDateModification() {
        return dateModification;
    }

    public void setDateModification(LocalDateTime dateModification) {
        this.dateModification = dateModification;
    }

    public Integer getTentativesConnexion() {
        return tentativesConnexion;
    }

    public void setTentativesConnexion(Integer tentativesConnexion) {
        this.tentativesConnexion = tentativesConnexion;
    }

    public LocalDateTime getDateVerrouillage() {
        return dateVerrouillage;
    }

    public void setDateVerrouillage(LocalDateTime dateVerrouillage) {
        this.dateVerrouillage = dateVerrouillage;
    }

    public String getTokenResetPassword() {
        return tokenResetPassword;
    }

    public void setTokenResetPassword(String tokenResetPassword) {
        this.tokenResetPassword = tokenResetPassword;
    }

    public LocalDateTime getDateExpirationToken() {
        return dateExpirationToken;
    }

    public void setDateExpirationToken(LocalDateTime dateExpirationToken) {
        this.dateExpirationToken = dateExpirationToken;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    // Méthodes utilitaires
    public void addRole(Role role) {
        this.roles.add(role);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    public boolean isAccountLocked() {
        if (this.statut == StatutUtilisateur.BLOQUE) {
            return true;
        }
        
        if (this.dateVerrouillage != null) {
            return LocalDateTime.now().isBefore(this.dateVerrouillage.plusMinutes(30));
        }
        
        return false;
    }

    public String getNomComplet() {
        return this.prenom + " " + this.nom;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Utilisateur)) return false;
        Utilisateur that = (Utilisateur) o;
        return Objects.equals(id, that.id) && Objects.equals(email, that.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, email);
    }

    @Override
    public String toString() {
        return "Utilisateur{" +
                "id=" + id +
                ", nom='" + nom + '\'' +
                ", prenom='" + prenom + '\'' +
                ", email='" + email + '\'' +
                ", statut=" + statut +
                '}';
    }
}