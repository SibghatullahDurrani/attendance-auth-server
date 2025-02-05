package com.main.face_recognition_auth_server.repositories;

import com.main.face_recognition_auth_server.domains.RegisteredClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JPARegisteredClientRepository extends JpaRepository<RegisteredClient, String> {
  @Query("""
          SELECT registeredClient FROM RegisteredClient registeredClient WHERE registeredClient.id = ?1
          """)
  Optional<RegisteredClient> findRegisteredClientById(String id);

  @Query("""
          SELECT registeredClient FROM RegisteredClient registeredClient WHERE registeredClient.clientId = ?1
          """)
  Optional<RegisteredClient> findRegisteredClientByClientId(String clientId);

  @Modifying
  @Query("""
           INSERT INTO RegisteredClient (clientId,clientSecret,redirectURI,id)
           VALUES(?1,?2,?3,?4)
          """)
  void insertIntoRegisteredClient(String clientId, String clientSecret, String redirectURI, String id);
}

