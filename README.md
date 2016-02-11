# EVE OAuth2 Example
A basic Java Spring Boot / Spring Security OAuth example app showing how to SSO with EVE Online and use CREST endpoints.

In it's current state it is just the code taken from [this](https://spring.io/guides/tutorials/spring-boot-oauth2/) Spring tutorial tweaked to
EVE Onlines OAuth2 SSO implementation as described [here](http://eveonline-third-party-documentation.readthedocs.org/en/latest/sso/intro/). It's
matching an app I registered on the EVE developers site, and which will be updated in terms of scopes according to future releases of this example repo.

## Usage

### Build with Maven:

_mvn package_

### Run with:

_java -jar eve-oauth2-example-0.0.2.jar_

### Point your browser to:

_localhost:8080_

### Known issues:

_- No actual CREST calls yet_

_- Doesn't really work in IGB due use of Angular.js_