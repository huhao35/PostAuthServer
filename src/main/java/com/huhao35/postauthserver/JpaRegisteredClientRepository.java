package com.huhao35.postauthserver;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.huhao35.postauthserver.OAuth2RegisteredClient;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 自定义 RegisteredClientRepository 实现（修复反序列化问题）
 */
@Component
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2RegisteredClientRepository jpaRepo;
    private final ObjectMapper objectMapper = getConfiguredObjectMapper();
    private ObjectMapper getConfiguredObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // 注册 Duration 序列化器：将 Duration 转为秒数（数字）
        SimpleModule module = new SimpleModule();
        module.addSerializer(Duration.class, new JsonSerializer<Duration>() {
            @Override
            public void serialize(Duration value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
                gen.writeNumber(value.getSeconds()); // 序列化为秒数（数字）
            }
        });
        mapper.registerModule(module);
        mapper.registerModule(new JavaTimeModule());
        mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        return mapper;
    }
    /**
     * 保存客户端配置（保持不变）
     */
    @Override
    public void save(RegisteredClient registeredClient) {
        try {
            OAuth2RegisteredClient entity = new OAuth2RegisteredClient();

            // 1. 基础字段
            entity.setId(registeredClient.getId());
            entity.setClientId(registeredClient.getClientId());
            entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
            entity.setClientSecret(registeredClient.getClientSecret());
            entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
            entity.setClientName(registeredClient.getClientName());

            // 2. 集合转逗号分隔字符串
            entity.setClientAuthenticationMethods(
                    registeredClient.getClientAuthenticationMethods().stream()
                            .map(ClientAuthenticationMethod::getValue)
                            .collect(Collectors.joining(","))
            );
            entity.setAuthorizationGrantTypes(
                    registeredClient.getAuthorizationGrantTypes().stream()
                            .map(AuthorizationGrantType::getValue)
                            .collect(Collectors.joining(","))
            );
            entity.setRedirectUris(
                    StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris())
            );
            entity.setScopes(
                    StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes())
            );

            // 3. 序列化 Settings 的 Map（关键修改：序列化 getSettings() 返回的 Map，而非对象本身）
            entity.setClientSettings(objectMapper.writeValueAsString(registeredClient.getClientSettings().getSettings()));
            entity.setTokenSettings(objectMapper.writeValueAsString(registeredClient.getTokenSettings().getSettings()));

            // 4. 保存到数据库
            jpaRepo.save(entity);

        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON序列化OAuth2客户端配置失败", e);
        } catch (Exception e) {
            throw new RuntimeException("保存OAuth2客户端到数据库失败", e);
        }
    }

    @Override
    public @Nullable RegisteredClient findById(String id) {
        return findByClientId(id);
    }
    @Override
    public RegisteredClient findByClientId(String clientId) {
        // 1. 查询数据库实体
        OAuth2RegisteredClient entity = jpaRepo.findByClientId(clientId).orElse(null);
        if (entity == null) {
            return null;
        }

        try {
            // 2. 反序列化 Settings 为 Map（关键：先转 Map，再通过构建器重建）
            TypeReference<Map<String, Object>> mapType = new TypeReference<>() {};
            Map<String, Object> clientSettingsMap = objectMapper.readValue(entity.getClientSettings(), mapType);
            Map<String, Object> tokenSettingsMap = objectMapper.readValue(entity.getTokenSettings(), mapType);

            // 3. 重建 ClientSettings（通过构建器，兼容无默认构造函数）
            ClientSettings clientSettings = ClientSettings.withSettings(clientSettingsMap).build();
            // 4. 重建 TokenSettings（通过构建器，兼容无默认构造函数）
            TokenSettings tokenSettings = TokenSettings.withSettings(tokenSettingsMap).build();

            // 5. 构建 RegisteredClient 对象
            return RegisteredClient.withId(entity.getId())
                    // 基础字段
                    .clientId(entity.getClientId())
                    .clientIdIssuedAt(entity.getClientIdIssuedAt())
                    .clientSecret(entity.getClientSecret())
                    .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                    .clientName(entity.getClientName())

                    // 客户端认证方式
                    .clientAuthenticationMethods(methods -> {
                        Set<ClientAuthenticationMethod> authMethods = parseCommaDelimitedString(
                                entity.getClientAuthenticationMethods(),
                                ClientAuthenticationMethod::new
                        );
                        methods.addAll(authMethods);
                    })

                    // 授权类型
                    .authorizationGrantTypes(types -> {
                        Set<AuthorizationGrantType> grantTypes = parseCommaDelimitedString(
                                entity.getAuthorizationGrantTypes(),
                                AuthorizationGrantType::new
                        );
                        types.addAll(grantTypes);
                    })

                    // 重定向URI
                    .redirectUris(uris -> {
                        Set<String> redirectUris = parseCommaDelimitedString(
                                entity.getRedirectUris(),
                                s -> s
                        );
                        uris.addAll(redirectUris);
                    })

                    // 作用域
                    .scopes(scopes -> {
                        Set<String> scopeSet = parseCommaDelimitedString(
                                entity.getScopes(),
                                s -> s
                        );
                        scopes.addAll(scopeSet);
                    })

                    // 关键：使用重建的 Settings 对象
                    .clientSettings(clientSettings)
                    .tokenSettings(tokenSettings)

                    // 构建
                    .build();

        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON反序列化OAuth2客户端配置失败", e);
        } catch (Exception e) {
            throw new RuntimeException("从数据库查询OAuth2客户端失败", e);
        }
    }

    /**
     * 通用工具方法：逗号分隔字符串转集合
     */
    private <T> Set<T> parseCommaDelimitedString(String str, java.util.function.Function<String, T> mapper) {
        if (!StringUtils.hasText(str)) {
            return Collections.emptySet();
        }
        return Arrays.stream(str.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .map(mapper)
                .collect(Collectors.toSet());
    }

    /**
     * 扩展方法：删除指定客户端
     */
}