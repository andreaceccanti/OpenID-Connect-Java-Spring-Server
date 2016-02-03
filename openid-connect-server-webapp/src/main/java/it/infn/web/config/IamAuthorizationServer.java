package it.infn.web.config;

import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.mitre.oauth2.token.StructuredScopeAwareOAuth2RequestValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.config.java.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

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

  @Autowired
  private ChainedTokenGranter chainedTokenGranter;

  @Autowired
  private JWTAssertionTokenGranter jwtAssertionTokenGranter;

  @Autowired
  private UserApprovalHandler tofuUserAppovalHandler;

  @Bean
  public OAuth2RequestValidator oauthRequestValidator() {

    return new StructuredScopeAwareOAuth2RequestValidator();
  }

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

    endpoints.pathMapping("/oauth/authorize", "/authorize")
      .pathMapping("/oauth/token", "/token")
      .pathMapping("/oauth/error", "/error");

    endpoints.setClientDetailsService(clientDetailsEntityService);
    endpoints.tokenServices(tokenService)
      .userApprovalHandler(tofuUserAppovalHandler)
      .requestValidator(oauthRequestValidator());

    endpoints.tokenGranter(chainedTokenGranter)
      .tokenGranter(jwtAssertionTokenGranter);

    endpoints.authorizationCodeServices(authCodeService);

  }

}
