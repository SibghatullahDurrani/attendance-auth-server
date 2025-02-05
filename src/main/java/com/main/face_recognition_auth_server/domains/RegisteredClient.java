package com.main.face_recognition_auth_server.domains;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "registered_clients")
public class RegisteredClient {
  @Id
  private String id;

  @Column(name = "client_id", length = 30)
  private String clientId;

  @Column(name = "client_secret")
  private String clientSecret;

  @Column(name = "redirect_uri", length = 500)
  private String redirectURI;
}
