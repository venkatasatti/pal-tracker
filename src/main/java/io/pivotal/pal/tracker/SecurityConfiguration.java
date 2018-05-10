package io.pivotal.pal.tracker;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private Boolean disableHttps;

    public SecurityConfiguration(@Value("${https.disabled}") Boolean disableHttps) {
        this.disableHttps = disableHttps;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (!disableHttps) {
            //redirect all the http to https
            http.requiresChannel().anyRequest().requiresSecure();
        }

        http
                .authorizeRequests().antMatchers("/**").hasRole("USER")
                // domain specific langauge
                .and()
                // using the http basic method only
                .httpBasic()
                .and()
                .csrf().disable();
        //cross site request forgery -- random token
        // for forms - csrf -- default enable

    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        //configures the users and roles - reading from database or LDAP or AD
        // parametrize from the somewhere else however the points is
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
}