package it.infn.web.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.service.impl.UriEncodedClientUserDetailsService;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
@Import(IamConfig.class)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  IamConfig iamConfig;

  @Autowired
  UserDetailsService clientUserDetailsManager;

  @Autowired
  UriEncodedClientUserDetailsService uriEncodedClientUserDetailsService;

  @Autowired
  CorsFilter corsFilter;

  @Bean
  public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {

    OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
    entryPoint.setRealmName("openidconnect");
    return entryPoint;
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

  public AuthenticationManager clientAuthenticationManager() {

    return null;

  }

  public AuthenticationManager clientAssertionAuthenticationManager() {

    return null;
  }

  @Bean
  public ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter() {

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

  @Bean
  public OAuth2TokenEntityService resourceServerFilter() {

    return new DefaultOAuth2ProviderTokenService();
  }

  @Override
  public void configure(final HttpSecurity http) throws Exception {

    http.antMatcher("/token").authorizeRequests()
      .antMatchers(HttpMethod.OPTIONS).permitAll().and().authorizeRequests()
      .antMatchers("/token").authenticated().and().httpBasic()
      .authenticationEntryPoint(oauthAuthenticationEntryPoint()).and()
      .addFilterAfter(clientAssertionEndpointFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .httpBasic().and()
      .addFilterAfter(clientCredentialsEndpointFilter(),
        BasicAuthenticationFilter.class)
      .httpBasic().and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http.exceptionHandling()
      .accessDeniedHandler(iamConfig.oauthAccessDeniedHandler());

    http.authorizeRequests()
      .antMatchers(
        "/#{T(org.mitre.openid.connect.web.JWKSetPublishingEndpoint).URL}**")
      .permitAll().and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http.authorizeRequests()
      .antMatchers(
        "/#{T(org.mitre.discovery.web.DiscoveryEndpoint).WELL_KNOWN_URL}/**")
      .permitAll().and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http.authorizeRequests().antMatchers("/resources/**").permitAll().and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint).URL}/**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterBefore(resourceServerFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .and().addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
      .and().authorizeRequests().antMatchers("/resources/**").permitAll();

    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint).URL}/**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterBefore(resourceServerFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .and().addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
      .and().authorizeRequests().antMatchers("/resources/**").permitAll();

    http
      .antMatcher("/#{T(org.mitre.openid.connect.web.UserInfoEndpoint).URL}**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterBefore(resourceServerFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .and().addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.RootController).API_URL}/**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.NEVER).and()
      .addFilterBefore(resourceServerFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .and().addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http.antMatcher("/#{T(org.mitre.oauth2.web.IntrospectionEndpoint).URL}**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterAfter(clientAssertionEndpointFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .httpBasic().and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
      .httpBasic().and().addFilterAfter(clientCredentialsEndpointFilter(),
        BasicAuthenticationFilter.class);

    http.antMatcher("/#{T(org.mitre.oauth2.web.RevocationEndpoint).URL}**")
      .httpBasic().authenticationEntryPoint(oauthAuthenticationEntryPoint())
      .and().sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
      .addFilterAfter(clientAssertionEndpointFilter(),
        AbstractPreAuthenticatedProcessingFilter.class)
      .httpBasic().and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
      .httpBasic().and().addFilterAfter(clientCredentialsEndpointFilter(),
        BasicAuthenticationFilter.class);

  }

  @Override
  protected void configure(final AuthenticationManagerBuilder auth)
    throws Exception {

    auth.jdbcAuthentication().dataSource(iamConfig.iamDataSource());
    super.configure(auth);
  }

}
