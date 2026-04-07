package com.huhao35.postauthserver;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@SpringBootApplication
public class PostAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PostAuthServerApplication.class, args);
    }
    @Bean
    public CommandLineRunner initOAuth2Client(
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder
    ) {
                return args -> {
                    // 1. 检查客户端是否已存在
                    RegisteredClient existingClient = registeredClientRepository.findByClientId("post-user-client");
                    if (existingClient == null) {
                        // 2. 配置令牌有效期（7.0.x必填，否则可能导致参数校验失败）
                        TokenSettings tokenSettings = TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofSeconds(300*2))
                                .refreshTokenTimeToLive(Duration.ofSeconds(3600))
                                .authorizationCodeTimeToLive(Duration.ofSeconds(300))
                                .deviceCodeTimeToLive(Duration.ofSeconds(300))
                                .reuseRefreshTokens(true)
                                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                                .build();
                        // 3. 构建客户端（补充TokenSettings，规范redirectUri）
                        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("post-user-client")
                                .clientName("Post-User-Client") // 补充有意义的客户端名称（非必需，但便于调试）
                                .clientSecret(passwordEncoder.encode("secret")) // 加密存储客户端密钥
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                // 规范的redirectUri：添加OAuth2回调后缀（和请求中的保持一致）
                                .redirectUri("http://localhost:7000/login/oauth2/code/post-user-client")
                                // 作用域配置（和请求中的scope参数匹配）
                                .scope("write")
                                .scope("read")
                                .scope(OidcScopes.OPENID)
                                // 客户端设置（保留授权确认，关闭PKCE）
                                .clientSettings(ClientSettings.builder()
                                        .requireAuthorizationConsent(true)
                                        .requireProofKey(false)
                                        .build())
                                // 关键：添加令牌配置（7.0.x必须）
                                .tokenSettings(tokenSettings)
                                .build();

                        // 4. 保存客户端并打印详细信息（便于调试）
                        registeredClientRepository.save(client);
                        System.out.println("=== 客户端初始化成功 ===");
                        System.out.println("Client ID: " + client.getClientId());
                        System.out.println("Redirect URIs: " + client.getRedirectUris());
                        System.out.println("Grant Types: " + client.getAuthorizationGrantTypes());
                        System.out.println("Scopes: " + client.getScopes());
                    } else {
                        System.out.println("=== 客户端已存在 ===");
                        System.out.println("Client ID: " + existingClient.getClientId());
                        System.out.println("Redirect URIs: " + existingClient.getRedirectUris());
                    }
                    RegisteredClient client = registeredClientRepository.findByClientId("command-line-tool");
                    if(client==null){
                        RegisteredClient new_client = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("command-line-tool")
                                .clientSecret(passwordEncoder.encode("secret"))
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .scope("write")
                                .scope("read")
                                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(3600*6)).build())
                                .build();
                        registeredClientRepository.save(new_client);
                        System.out.println("=== 客户端初始化成功 ===");
                        System.out.println("Client ID: " + new_client.getClientId());
                        System.out.println("Redirect URIs: " + new_client.getRedirectUris());
                        System.out.println("Grant Types: " + new_client.getAuthorizationGrantTypes());
                        System.out.println("Scopes: " + new_client.getScopes());
                    }else{
                        System.out.println("=== 客户端已存在 ===");
                        System.out.println("Client ID: " + client.getClientId());
                        System.out.println("Redirect URIs: " + client.getRedirectUris());
                    }
                };
    }
}
