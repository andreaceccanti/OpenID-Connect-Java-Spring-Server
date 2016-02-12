package org.mitre.web.config;

import java.util.concurrent.Executor;

import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

@Configuration
@EnableScheduling
public class SchedulingConfig implements SchedulingConfigurer {

  @Autowired
  private Executor taskScheduler;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  private ApprovedSiteService defaultApprovedSiteService;

  @Autowired
  @Qualifier("defaultOAuth2AuthorizationCodeService")
  private AuthorizationCodeServices codeService;

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredTokens() {

    tokenService.clearExpiredTokens();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredSites() {

    defaultApprovedSiteService.clearExpiredSites();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredAuthzCodes() {

    ((DefaultOAuth2AuthorizationCodeService) codeService)
      .clearExpiredAuthorizationCodes();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {

    taskRegistrar.setScheduler(taskScheduler);
  }

}
