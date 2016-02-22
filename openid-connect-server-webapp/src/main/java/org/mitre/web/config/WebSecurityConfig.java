package org.mitre.web.config;

import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private AuthenticationTimeStamper authenticationTimeStamper;

  @Autowired
  private CorsFilter corsFilter;

  @Autowired
  private DataSource iamDataSource;

  @Autowired
  private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

  @Autowired
  private OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

  @Autowired
  @Qualifier("clientUserDetailsService")
  private UserDetailsService clientUserDetailsService;

  @Autowired
  @Qualifier("uriEncodedClientUserDetailsService")
  private UserDetailsService uriEncodedClientUserDetailsService;

  @Autowired
  private RequestMatcher clientAuthMatcher;

  @Bean
  public ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter()
    throws Exception {

    ClientCredentialsTokenEndpointFilter tokenFilter = new ClientCredentialsTokenEndpointFilter(
      "/token");
    tokenFilter.setAuthenticationManager(clientAuthenticationManager());
    tokenFilter.setRequiresAuthenticationRequestMatcher(clientAuthMatcher);

    return tokenFilter;
  }

  @Bean
  public JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter() {

    JWTBearerClientAssertionTokenEndpointFilter tokenEndpointFilter = new JWTBearerClientAssertionTokenEndpointFilter(
      clientAuthMatcher);
    tokenEndpointFilter
      .setAuthenticationManager(clientAssertionAuthenticationManager());

    return tokenEndpointFilter;
  }

  @Bean
  public AuthenticationProvider clientAssertionAuthenticationProvider() {

    return new JWTBearerAuthenticationProvider();
  }

  public AuthenticationManager clientAuthenticationManager() throws Exception {

    List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
    DaoAuthenticationProvider daoAP = new DaoAuthenticationProvider();

    daoAP.setUserDetailsService(clientUserDetailsService);
    providers.add(daoAP);

    daoAP = new DaoAuthenticationProvider();
    daoAP.setUserDetailsService(uriEncodedClientUserDetailsService);
    providers.add(daoAP);

    return new ProviderManager(providers);
  }

  public AuthenticationManager clientAssertionAuthenticationManager() {

    List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
    providers.add(clientAssertionAuthenticationProvider());

    return new ProviderManager(providers);
  }

  @Override
  public void configure(final HttpSecurity http) throws Exception {

    // @formatter:off
   
    http
      .authorizeRequests()
        .anyRequest().permitAll()
        .and()
      .formLogin()
        .loginPage("/login")
        .failureUrl("/login?error=failure")
        .successHandler(authenticationTimeStamper)
        .permitAll()
        .and()
      .logout()
        .logoutUrl("/logout")
        .permitAll()
        .and()
      .anonymous()
        .and()
      .headers()
        .frameOptions().deny()
        .and()
      .csrf()
        .disable();
    
    // @formatter:on
  }

  @Override
  public void configure(final WebSecurity web) throws Exception {

    web.ignoring().antMatchers("/resources/**", "/images/**");
    web.expressionHandler(new OAuth2WebSecurityExpressionHandler());
  }

  @Override
  protected void configure(final AuthenticationManagerBuilder auth)
    throws Exception {

    auth.jdbcAuthentication().dataSource(iamDataSource);
    super.configure(auth);
  }

}
