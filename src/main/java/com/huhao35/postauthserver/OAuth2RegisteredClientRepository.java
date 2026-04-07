package com.huhao35.postauthserver;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Convert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

import java.security.Timestamp;
import java.time.Instant;
import java.util.Optional;

public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClient,String> {
    Optional<OAuth2RegisteredClient> findByClientId(String clientId);
}
