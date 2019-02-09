package org.synyx.urlaubsverwaltung.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.synyx.urlaubsverwaltung.security.SimpleAuthenticationProvider;

import java.util.Optional;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Environment environment;


    private final SimpleAuthenticationProvider simpleAuthenticationProvider;
    private final UserDetailsContextMapper personContextMapper;

    @Autowired(required = false)
    public WebSecurityConfig(Environment environment,
                             Optional<SimpleAuthenticationProvider> simpleAuthenticationProvider,
                             Optional<UserDetailsContextMapper> personContextMapper) {

        this.environment = environment;
        this.simpleAuthenticationProvider = simpleAuthenticationProvider.orElse(null);
        this.personContextMapper = personContextMapper.orElse(null);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);

        http.authorizeRequests()
            // API
            .antMatchers("/api/sicknotes/**").hasAuthority("OFFICE")
            .antMatchers("/api/**").hasAuthority("USER")
            // WEB
            .antMatchers("/web/overview").hasAuthority("USER")
            .antMatchers("/web/application/**").hasAuthority("USER")
            .antMatchers("/web/sicknote/**").hasAuthority("USER")
            .antMatchers("/web/staff/**").hasAuthority("USER")
            .antMatchers("/web/overtime/**").hasAuthority("USER")
            .antMatchers("/web/department/**").hasAuthority("USER")
            .antMatchers("/web/settings/**").hasAuthority("USER")
            .antMatchers("/web/google-api-handshake/**").hasAuthority("USER")
            // sprint boot actuator
            .antMatchers("${management.context-path}/health").permitAll()
            .antMatchers("${management.context-path}/**").hasAnyAuthority("${management.security.roles}")
            // OPEN
            .antMatchers("/css/**").permitAll()
            .antMatchers("/fonts/**").permitAll()
            .antMatchers("/images/**").permitAll()
            .antMatchers("/lib/**").permitAll()
                .anyRequest().authenticated()
            .and().formLogin().loginPage("/login").permitAll().defaultSuccessUrl("/web/overview", false).failureUrl("/login?login_error=1")
            .and()
            .logout().logoutUrl("/logout").logoutSuccessUrl("/login")
            .and()
            .csrf().disable()
            // TODO: dev-env
            .headers().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authBuilder) throws Exception {

        String auth = this.environment.getProperty("auth");

        switch (auth) {
            case "default":
                authBuilder.authenticationProvider(this.simpleAuthenticationProvider);
                break;
            case "activeDirectory":
                authBuilder.authenticationProvider(this.getActiveDirectoryLdapAuthenticationProvider());
                break;
            case "ldap":
                configureLdap(authBuilder);
                break;
            default:
                throw new IllegalStateException("unknown authentication provider: " + auth);
        }
    }

    private void configureLdap(AuthenticationManagerBuilder authBuilder) throws Exception {
        authBuilder.ldapAuthentication()
                .contextSource()
                    .url(this.environment.getProperty("uv.security.ldap.url") + "/" + this.environment.getProperty("uv.security.ldap.base"))
                    .managerDn(this.environment.getProperty("uv.security.ldap.managerDn"))
                    .managerPassword(this.environment.getProperty("uv.security.ldap.managerPassword"))
            .and()
                .userDetailsContextMapper(this.personContextMapper)
                .userSearchBase(this.environment.getProperty("uv.security.ldap.userSearchBase"))
                .userSearchFilter(this.environment.getProperty("uv.security.ldap.userSearchFilter"));
    }


    private ActiveDirectoryLdapAuthenticationProvider getActiveDirectoryLdapAuthenticationProvider() {
        String domain = this.environment.getProperty("uv.security.activeDirectory.domain");
        String url = this.environment.getProperty("uv.security.activeDirectory.url");
        ActiveDirectoryLdapAuthenticationProvider result = new ActiveDirectoryLdapAuthenticationProvider(domain, url);
        result.setUserDetailsContextMapper(this.personContextMapper);
        return result;
    }

}
