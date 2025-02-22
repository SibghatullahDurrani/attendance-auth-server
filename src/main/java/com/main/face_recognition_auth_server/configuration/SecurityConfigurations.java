package com.main.face_recognition_auth_server.configuration;

import com.main.face_recognition_auth_server.filters.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfigurations {

  //http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://oidcdebugger.com/debug&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&&code_challenge_method=S256
  // qIRFnJ6Dm5DWWrghlk8F553hlCOvL--pYjtJIy9PVIIBkr4auExOpINGGkgB-bNbBMA70QTFiORLz1BQ43rJMlg2ZgL5Bn330J8B7lh_6REvD8JkbmnYaWnq4KnMUxGR

  @Bean
  @Order(1)
  public SecurityFilterChain applicationSecurityFilterChain(HttpSecurity http) throws Exception {
    // TODO: Dont disable cors
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();
    http.addFilterBefore(new CorsFilter(), ChannelProcessingFilter.class);
    http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, (authorizationServer) ->
                    authorizationServer.oidc(Customizer.withDefaults()))
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    http.exceptionHandling((e) ->
            e.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//    http.cors(AbstractHttpConfigurer::disable);
    http.cors(c -> {
      CorsConfigurationSource source = _ -> {
        CorsConfiguration cc = new CorsConfiguration();
        cc.setAllowCredentials(true);
        cc.setAllowedOrigins(List.of("http://127.0.0.1:4200"));
        cc.setAllowedHeaders(List.of("*"));
        cc.setAllowedMethods(List.of("*"));
        return cc;
      };
      c.configurationSource(source);
    });
    http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return context -> {
      List<GrantedAuthority> authorities = context.getPrincipal().getAuthorities().stream().collect(Collectors.toUnmodifiableList());
      List<String> authoritiesString = new ArrayList<String>();
      for (GrantedAuthority authority : authorities) {
        authoritiesString.add(authority.getAuthority());
      }
      JwtClaimsSet.Builder claims = context.getClaims();
      claims.claim("ROLES", authoritiesString);
    };
  }
}
