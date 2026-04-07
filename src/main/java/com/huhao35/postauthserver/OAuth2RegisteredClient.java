package com.huhao35.postauthserver;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Arrays;

@Entity
@Table(name = "oauth2_registered_client")
@Data
public class OAuth2RegisteredClient {

    @Id
    private String id;

    private String clientId;               // 客户端ID（如：my-client）
    private Instant clientIdIssuedAt;      // 创建时间

    private String clientSecret;           // 客户端密码（加密后）
    private Instant clientSecretExpiresAt; // 过期时间，可为null

    private String clientName;             // 客户端名称（展示用）

    @Column(length = 1000)
    private String clientAuthenticationMethods; // 认证方式：client_secret_basic等

    @Column(length = 1000)
    private String authorizationGrantTypes;     // 授权类型：authorization_code,refresh_token

    @Column(length = 1000)
    private String redirectUris;                 // 回调地址

    @Column(length = 1000)
    private String scopes;                       // 权限范围

    @Column(length = 2000)
    private String clientSettings;               // 客户端配置（JSON）

    @Column(length = 2000)
    private String tokenSettings;



}
