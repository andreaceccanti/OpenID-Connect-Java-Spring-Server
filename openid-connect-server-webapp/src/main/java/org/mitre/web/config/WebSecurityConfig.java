package org.mitre.web.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.mitre.oauth2.service.impl.DefaultClientUserDetailsService;
import org.mitre.oauth2.service.impl.UriEncodedClientUserDetailsService;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  IamConfig iamConfig;

  @Autowired
  AuthenticationTimeStamper authenticationTimeStamper;

  public UserDetailsService clientUserDetailsManager() {

    return new DefaultClientUserDetailsService();
  }

  public UserDetailsService uriEncodedClientUserDetailsService() {

    return new UriEncodedClientUserDetailsService();
  }

  @Bean
  public Http403ForbiddenEntryPoint http403EntryPoint() {

    return new Http403ForbiddenEntryPoint();
  }

  @Bean
  public WebResponseExceptionTranslator oauth2ExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean
  public RequestMatcher clientAuthMatcher() {

    Set<String> endpoints = new LinkedHashSet<String>(
      Arrays.asList("/introspect", "/revoke", "/token"));
    return new MultiUrlRequestMatcher(endpoints);
  }

  public AuthenticationManager clientAuthenticationManager() throws Exception {

    List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
    DaoAuthenticationProvider daoAP = new DaoAuthenticationProvider();

    daoAP.setUserDetailsService(clientUserDetailsManager());
    providers.add(daoAP);

    daoAP = new DaoAuthenticationProvider();
    daoAP.setUserDetailsService(uriEncodedClientUserDetailsService());
    providers.add(daoAP);

    return new ProviderManager(providers);

  }

  public AuthenticationManager clientAssertionAuthenticationManager() {

    List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
    providers.add(clientAssertionAuthenticationProvider());

    return new ProviderManager(providers);

  }

  @Bean
  public ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter()
    throws Exception {

    ClientCredentialsTokenEndpointFilter tokenFilter = new ClientCredentialsTokenEndpointFilter();
    tokenFilter.setAuthenticationManager(clientAuthenticationManager());
    tokenFilter.setRequiresAuthenticationRequestMatcher(clientAuthMatcher());

    return tokenFilter;
  }

  @Bean
  public JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter() {

    JWTBearerClientAssertionTokenEndpointFilter tokenEndpointFilter = new JWTBearerClientAssertionTokenEndpointFilter(
      clientAuthMatcher());
    tokenEndpointFilter
      .setAuthenticationManager(clientAssertionAuthenticationManager());

    return tokenEndpointFilter;
  }

  @Bean
  public AuthenticationProvider clientAssertionAuthenticationProvider() {

    return new JWTBearerAuthenticationProvider();
  }

  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {

    return super.authenticationManagerBean();
  }

  @Override
  public void configure(final HttpSecurity http) throws Exception {

    // ResourceServerSecurityConfigurer resources = new
    // ResourceServerSecurityConfigurer();
    // resources.tokenServices(iamConfig.tokenService);
    // http.apply(resources);

    // @formatter:off
    http
      .formLogin()
        .loginPage("/login")
        .failureUrl("/login?error=failure")
        .successHandler(authenticationTimeStamper)
        .and()
      .authorizeRequests()
        .antMatchers("/authorize").hasRole("USER")
        .antMatchers("/**").permitAll()
//        .anyRequest().authenticated()
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
      .csrf();
    
/*
    http.antMatcher("/token").authorizeRequests()
      .antMatchers(HttpMethod.OPTIONS).permitAll()
      .and().authorizeRequests()
      .antMatchers("/token").authenticated()
      .and().httpBasic()
      .authenticationEntryPoint(iamConfig.oauthAuthenticationEntryPoint())
      .and()
      .addFilterAfter(clientAssertionEndpointFilter(), AbstractPreAuthenticatedProcessingFilter.class).httpBasic()
      .and()
      .addFilterAfter(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class).httpBasic()
      .and().addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class);

    http.exceptionHandling()
      .accessDeniedHandler(iamConfig.oauthAccessDeniedHandler());

    http.authorizeRequests()
      .antMatchers( "/#{T(org.mitre.openid.connect.web.JWKSetPublishingEndpoint).URL}**").permitAll()
      .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and().addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class);

    http.authorizeRequests()
      .antMatchers("/#{T(org.mitre.discovery.web.DiscoveryEndpoint).WELL_KNOWN_URL}/**").permitAll()
      .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and().addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class);

    http.authorizeRequests()
      .antMatchers("/resources/**").permitAll()
      .and().addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class);

    http
      .antMatcher("/#{T(org.mitre.oauth2.web.IntrospectionEndpoint).URL}**").httpBasic()
      .authenticationEntryPoint(iamConfig.oauthAuthenticationEntryPoint())
      .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and().addFilterAfter(clientAssertionEndpointFilter(), AbstractPreAuthenticatedProcessingFilter.class)
      .httpBasic()
      .and()
      .addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class)
      .httpBasic()
      .and().addFilterAfter(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class);

    http
      .antMatcher("/#{T(org.mitre.oauth2.web.RevocationEndpoint).URL}**")
      .httpBasic()
      .authenticationEntryPoint(iamConfig.oauthAuthenticationEntryPoint())
      .and()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and()
      .addFilterAfter(clientAssertionEndpointFilter(), AbstractPreAuthenticatedProcessingFilter.class).httpBasic()
      .and()
      .addFilterAfter(iamConfig.corsFilter(), SecurityContextPersistenceFilter.class).httpBasic()
      .and()
      .addFilterAfter(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class);
      */
    // @formatter:on
  }

  @Override
  public void configure(final WebSecurity web) throws Exception {

    web.ignoring().antMatchers("/resources/**", "/images/**");
  }

  @Override
  protected void configure(final AuthenticationManagerBuilder auth)
    throws Exception {

    auth.jdbcAuthentication().dataSource(iamConfig.iamDataSource());
    super.configure(auth);
  }

}
