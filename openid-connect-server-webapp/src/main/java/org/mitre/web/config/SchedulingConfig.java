package org.mitre.web.config;

import java.util.concurrent.Executor;

import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

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
  private DefaultOAuth2AuthorizationCodeService authCodeService;

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

    authCodeService.clearExpiredAuthorizationCodes();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {

    taskRegistrar.setScheduler(taskScheduler);
  }

}
