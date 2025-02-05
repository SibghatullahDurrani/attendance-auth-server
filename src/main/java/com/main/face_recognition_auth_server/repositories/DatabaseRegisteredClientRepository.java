package com.main.face_recognition_auth_server.repositories;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Repository
public class DatabaseRegisteredClientRepository implements RegisteredClientRepository {
  private final JPARegisteredClientRepository registeredClientRepository;

  public DatabaseRegisteredClientRepository(JPARegisteredClientRepository registeredClientRepository) {
    this.registeredClientRepository = registeredClientRepository;
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    Optional<String> optionalRedirectUri = registeredClient.getRedirectUris().stream().findFirst();
    optionalRedirectUri.ifPresent(redirectUri ->
            registeredClientRepository.insertIntoRegisteredClient(
                    registeredClient.getClientId(),
                    registeredClient.getClientSecret(),
                    redirectUri,
                    registeredClient.getId()
            )
    );
  }

  @Override
  public RegisteredClient findById(String id) {
    Optional<com.main.face_recognition_auth_server.domains.RegisteredClient> optionalRegisteredClient = registeredClientRepository.findRegisteredClientById(id);
    return getRegisteredClient(optionalRegisteredClient);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    Optional<com.main.face_recognition_auth_server.domains.RegisteredClient> optionalRegisteredClient = registeredClientRepository.findRegisteredClientByClientId(clientId);
    return getRegisteredClient(optionalRegisteredClient);
  }

  private RegisteredClient getRegisteredClient(Optional<com.main.face_recognition_auth_server.domains.RegisteredClient> optionalRegisteredClient) {
    if (optionalRegisteredClient.isPresent()) {
      com.main.face_recognition_auth_server.domains.RegisteredClient client = optionalRegisteredClient.get();
      return RegisteredClient
              .withId(client.getId())
              .clientId(client.getClientId())
              .clientSecret(client.getClientSecret())
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
              .redirectUri(client.getRedirectURI())
              .scope(OidcScopes.OPENID)
              .tokenSettings(TokenSettings.builder()
                      .accessTokenTimeToLive(Duration.ofHours(12))
                      .build())
              .build();
    } else {
      return null;
    }
  }
}
