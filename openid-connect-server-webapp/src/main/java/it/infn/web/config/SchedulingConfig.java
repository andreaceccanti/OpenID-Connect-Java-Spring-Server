package it.infn.web.config;

import java.util.concurrent.Executor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

@EnableScheduling
@Import(IamConfig.class)
public class SchedulingConfig implements SchedulingConfigurer {

  @Autowired
  IamConfig iamConfig;

  @Autowired
  private Executor taskScheduler;

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredTokens() {

    iamConfig.tokenService.clearExpiredTokens();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredSites() {

    iamConfig.defaultApprovedSiteService.clearExpiredSites();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredAuthzCodes() {

    iamConfig.codeService().clearExpiredAuthorizationCodes();
  }

  @Override
  public void configureTasks(final ScheduledTaskRegistrar taskRegistrar) {

    taskRegistrar.setScheduler(taskScheduler);

  }

}
