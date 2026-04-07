package com.huhao35.postauthserver;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.boot.models.annotations.internal.GeneratedAnnotation;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.hibernate.annotations.SQLRestriction;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;
@Data
@Entity
@SQLRestriction("available = 1")
public class User implements Serializable, UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @JsonIgnore
    private String password;
    private Date createdAt;
    @PrePersist
    public void prep(){
        createdAt = new Date();
        available = Boolean.TRUE;
    }
    @Column(unique = true)
    private String fullName;
    @Column(columnDefinition = "TEXT")
    private String intro;
    @Column(nullable = false)
    private Boolean available;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public @Nullable String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return fullName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked(){return true;}
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 密码不过期
    }

    @Override
    public boolean isEnabled() {
        return true; // 账号启用
    }

}
