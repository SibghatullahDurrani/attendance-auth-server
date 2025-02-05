package com.main.face_recognition_auth_server.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Configuration
public class RSAKeyConfiguration {
  @Value("${RSA.privateKey}")
  private String privateKeyString;
  @Value("${RSA.publicKey}")
  private String publicKeyString;

  @Bean
  public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException, InvalidKeySpecException {

    byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

    byte[] privateBytes = Base64.getDecoder().decode(privateKeyString);
    PKCS8EncodedKeySpec prvKeySpec = new PKCS8EncodedKeySpec(privateBytes);
    RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(prvKeySpec);


    RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }
}
