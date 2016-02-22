package org.mitre.web.config;

import javax.sql.DataSource;

import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

@Configuration
@EnableAuthorizationServer
public class IamAuthorizationServer
  extends AuthorizationServerConfigurerAdapter {

  @Autowired
  private DefaultOAuth2ClientDetailsEntityService clientDetailsEntityService;

  @Autowired
  private ChainedTokenGranter chainedTokenGranter;

  @Autowired
  private JWTAssertionTokenGranter jwtAssertionTokenGranter;

  @Autowired
  private DataSource iamDataSource;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private OAuth2RequestValidator oauth2RequestValidator;

  @Autowired
  private UserApprovalHandler tofuUserAppovalHandler;

  @Autowired
  private AuthorizationCodeServices authCodeService;

  @Override
  public void configure(final ClientDetailsServiceConfigurer clients)
    throws Exception {

    clients.jdbc(iamDataSource);
  }

  @Override
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints)
    throws Exception {

    endpoints.pathMapping("/oauth/authorize", "/authorize")
      .pathMapping("/oauth/token", "/token")
      .pathMapping("/oauth/error", "/error");

    endpoints.clientDetailsService(clientDetailsEntityService);
    endpoints.tokenServices(tokenService)
      .userApprovalHandler(tofuUserAppovalHandler)
      .requestValidator(oauth2RequestValidator);

    endpoints.tokenGranter(chainedTokenGranter)
      .tokenGranter(jwtAssertionTokenGranter);

    endpoints.authorizationCodeServices(authCodeService);

  }

  @Override
  public void configure(final AuthorizationServerSecurityConfigurer oauthServer)
    throws Exception {

    oauthServer.allowFormAuthenticationForClients();
  }

}
