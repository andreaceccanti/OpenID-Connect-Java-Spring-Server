package org.mitre.web.config;

import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.web.CorsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableResourceServer
public class IamResourceServer extends ResourceServerConfigurerAdapter {

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private CorsFilter corsFilter;

  @Autowired
  private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

  @Override
  public void configure(final ResourceServerSecurityConfigurer resources)
    throws Exception {

    resources.tokenServices(tokenService);
  }

  @Override
  public void configure(final HttpSecurity http) throws Exception {

    // @formatter:off
    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint).URL}/**")
      .httpBasic()
      .authenticationEntryPoint(oauthAuthenticationEntryPoint)
      .and()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class).httpBasic()
      .and().authorizeRequests().antMatchers("/resources/**").permitAll();

    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint).URL}/**")
      .httpBasic()
      .authenticationEntryPoint(oauthAuthenticationEntryPoint)
      .and()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class).httpBasic()
      .and().authorizeRequests().antMatchers("/resources/**").permitAll();

    http
      .antMatcher("/#{T(org.mitre.openid.connect.web.UserInfoEndpoint).URL}**")
      .httpBasic()
      .authenticationEntryPoint(oauthAuthenticationEntryPoint)
      .and()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and()
      .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);

    http
      .antMatcher(
        "/#{T(org.mitre.openid.connect.web.RootController).API_URL}/**")
      .httpBasic()
      .authenticationEntryPoint(oauthAuthenticationEntryPoint)
      .and()
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
      .and().addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class);
    // @formatter:on

  }
}
