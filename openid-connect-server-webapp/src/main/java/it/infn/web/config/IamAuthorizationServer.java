package it.infn.web.config;

import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
@Import(IamConfig.class)
public class IamAuthorizationServer
  extends AuthorizationServerConfigurerAdapter {

  @Autowired
  IamConfig iamConfig;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private DefaultOAuth2AuthorizationCodeService authCodeService;

  @Autowired
  private DefaultOAuth2ClientDetailsEntityService clientDetailsEntityService;

  @Override
  public void configure(final ClientDetailsServiceConfigurer clients)
    throws Exception {

    clients.jdbc(iamConfig.iamDataSource());

  }

  @Override
  public void configure(final AuthorizationServerSecurityConfigurer security)
    throws Exception {

  }

  @Override
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints)
    throws Exception {

    endpoints.tokenServices(tokenService);
    endpoints.setClientDetailsService(clientDetailsEntityService);
    endpoints.authorizationCodeServices(authCodeService);

  }

}
