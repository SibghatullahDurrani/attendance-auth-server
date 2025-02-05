package com.main.face_recognition_auth_server.repositories;

import com.main.face_recognition_auth_server.domains.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<User, Long> {
  @Query("""
          SELECT user FROM User user WHERE user.username = ?1
          """)
  Optional<User> findUserByUsername(String username);
}
