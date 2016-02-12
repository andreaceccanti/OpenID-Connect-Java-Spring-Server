package org.mitre.web.config;

import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.mitre.oauth2.token.StructuredScopeAwareOAuth2RequestValidator;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

@Configuration
@EnableAuthorizationServer
public class IamAuthorizationServer
  extends AuthorizationServerConfigurerAdapter {

  @Autowired
  private IamConfig iamConfig;

  @Autowired
  private DefaultOAuth2ClientDetailsEntityService clientDetailsEntityService;

  @Bean
  public AuthorizationCodeServices authCodeService() {

    return new DefaultOAuth2AuthorizationCodeService();
  }

  private OAuth2RequestFactory requestFactory() {

    return new DefaultOAuth2RequestFactory(clientDetailsEntityService);
  }

  @Bean
  public ChainedTokenGranter chainedTokenGranter() {

    return new ChainedTokenGranter(iamConfig.tokenService,
      clientDetailsEntityService, requestFactory());
  }

  @Bean
  public JWTAssertionTokenGranter jwtAssertionTokenGranter() {

    return new JWTAssertionTokenGranter(iamConfig.tokenService,
      clientDetailsEntityService, requestFactory());
  }

  @Bean
  public UserApprovalHandler tofuUserAppovalHandler() {

    return new TofuUserApprovalHandler();
  }

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
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints)
    throws Exception {

    endpoints.pathMapping("/oauth/authorize", "/authorize")
      .pathMapping("/oauth/token", "/token")
      .pathMapping("/oauth/error", "/error");

    endpoints.clientDetailsService(clientDetailsEntityService);
    endpoints.tokenServices(iamConfig.tokenService)
      .userApprovalHandler(tofuUserAppovalHandler())
      .requestValidator(oauthRequestValidator());

    endpoints.tokenGranter(chainedTokenGranter())
      .tokenGranter(jwtAssertionTokenGranter());

    endpoints.authorizationCodeServices(authCodeService());

  }

}
