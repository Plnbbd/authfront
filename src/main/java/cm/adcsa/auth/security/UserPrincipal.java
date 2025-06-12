package cm.adcsa.auth.security;

import cm.adcsa.auth.entity.Utilisateur;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails {

    private Long id;
    private String nom;
    private String prenom;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private boolean accountNonLocked;

    public UserPrincipal(Long id, String nom, String prenom, String email, String password,
                        Collection<? extends GrantedAuthority> authorities, boolean accountNonLocked) {
        this.id = id;
        this.nom = nom;
        this.prenom = prenom;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
        this.accountNonLocked = accountNonLocked;
    }

    public static UserPrincipal create(Utilisateur utilisateur) {
        List<GrantedAuthority> authorities = utilisateur.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getNom()))
                .collect(Collectors.toList());

        return new UserPrincipal(
                utilisateur.getId(),
                utilisateur.getNom(),
                utilisateur.getPrenom(),
                utilisateur.getEmail(),
                utilisateur.getMotDePasse(),
                authorities,
                !utilisateur.isAccountLocked()
        );
    }

    public Long getId() {
        return id;
    }

    public String getNom() {
        return nom;
    }

    public String getPrenom() {
        return prenom;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}