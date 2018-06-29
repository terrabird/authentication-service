package com.terrabird.aspect;

/**
 * @author Praveer Das
 */

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

/**
 * @author Praveer Das
 */
@Aspect
@Configuration
public class LoggingAspect {

    private final org.slf4j.Logger log = LoggerFactory.getLogger(this.getClass());

    @Pointcut("execution(* com.terrabird.controller..*(..))")
    public void logControllerMethods() {}
    @Pointcut("execution(* com.terrabird.service..*(..))")
    public void logServiceMethods() {}
    @Pointcut("execution(* com.terrabird.dao..*(..))")
    public void logDAOMethods() {}
    @Pointcut("execution(* com.terrabird.*.*(..))")
    public void logExceptionForAllMethods(){}


    @Before("logControllerMethods()")
    public void logControllerEntryMethods(JoinPoint joinPoint) {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName());
        log.info("Agruments Passed=" + Arrays.toString(joinPoint.getArgs()));
    }

    @After("logControllerMethods()")
    public void logControllerExitMethods(JoinPoint joinPoint) {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName() + " exited.");
    }

    @Before("logServiceMethods()")
    public void logServiceEntryMethods(JoinPoint joinPoint)
    {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName());
        log.info("Agruments Passed=" + Arrays.toString(joinPoint.getArgs()));
    }

    @After("logServiceMethods()")
    public void logServiceExitMethods(JoinPoint joinPoint) {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName() + " exited.");
    }

    @Before("logDAOMethods()")
    public void logEntryAdvice(JoinPoint joinPoint) {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName());
        log.info("Agruments Passed=" + Arrays.toString(joinPoint.getArgs()));
    }

    @After("logDAOMethods()")
    public void logExitAdvice(JoinPoint joinPoint) {
        log.info(joinPoint.getTarget().getClass().getName() + " :: " + joinPoint.getSignature().getName() + " exited.");
    }

    @AfterThrowing(pointcut = "logExceptionForAllMethods()" , throwing="ex")
    public void afterThrowingAdviceForAllMethods(JoinPoint joinPoint, Exception ex) throws Throwable {
        log.info("Exception Caught : " + ex);
    }

}
