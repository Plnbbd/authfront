package cm.adcsa.auth.dto.response;

import java.time.LocalDateTime;
import java.util.List;

public class LoginResponse {

    private String accessToken;
    private String refreshToken;
    private long expiration;
    private UtilisateurDto utilisateur;

    public LoginResponse(String accessToken, String refreshToken, long expiration, UtilisateurDto utilisateur) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiration = expiration;
        this.utilisateur = utilisateur;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    public UtilisateurDto getUtilisateur() {
        return utilisateur;
    }

    public void setUtilisateur(UtilisateurDto utilisateur) {
        this.utilisateur = utilisateur;
    }

    public static class UtilisateurDto {
        private Long id;
        private String nom;
        private String prenom;
        private String email;
        private String statut;
        private LocalDateTime derniereConnexion;
        private List<String> roles;

        public UtilisateurDto(Long id, String nom, String prenom, String email, String statut, 
                             LocalDateTime derniereConnexion, List<String> roles) {
            this.id = id;
            this.nom = nom;
            this.prenom = prenom;
            this.email = email;
            this.statut = statut;
            this.derniereConnexion = derniereConnexion;
            this.roles = roles;
        }

        // Getters
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        
        public String getNom() { return nom; }
        public void setNom(String nom) { this.nom = nom; }
        
        public String getPrenom() { return prenom; }
        public void setPrenom(String prenom) { this.prenom = prenom; }
        
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        
        public String getStatut() { return statut; }
        public void setStatut(String statut) { this.statut = statut; }
        
        public LocalDateTime getDerniereConnexion() { return derniereConnexion; }
        public void setDerniereConnexion(LocalDateTime derniereConnexion) { this.derniereConnexion = derniereConnexion; }
        
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }
}