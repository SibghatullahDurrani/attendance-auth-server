package com.main.face_recognition_auth_server.services;

import com.main.face_recognition_auth_server.domains.User;
import com.main.face_recognition_auth_server.repositories.UsersRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {
  private final UsersRepository usersRepository;

  public DatabaseUserDetailsService(UsersRepository usersRepository) {
    this.usersRepository = usersRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Optional<User> optionalUser = usersRepository.findUserByUsername(username);
    if (optionalUser.isEmpty()) {
      throw new UsernameNotFoundException("Authentication failed!");
    }
    User user = optionalUser.get();
    List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole()));
    return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
  }
}
