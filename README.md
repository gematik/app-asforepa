<img align="right" width="250" height="47" src="Gematik_Logo_Flag_With_Background.png"/> <br/> 

# ASFOREPA

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
       <ul>
        <li><a href="#release-notes">Release Notes</a></li>
      </ul>
	</li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#additional-notes-and-disclaimer-from-gematik-gmbh">Additional Notes</a></li>
  </ol>
</details>

## About The Project

Authorization Server for ePA

### Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) for all information regarding the (newest) releases.

## Getting Started

### Prerequisites

- Java JDK 17+
- Maven

### Installation

To quickly check your build environment without running any tests (just build asforepa server and
testsuite) do in
project root:

`mvn clean package -Dskip.unittests`

To build the docker image do:
`mvn clean package -Dskip.dockerbuild=false`

### build project and run unit tests (skip integration tests == skip testsuite execution)

`mvn clean test -Dskip.inttests`

### build project and run integration tests

`mvn clean verify`

The keys `asforepa/src/test/resources/833621999741600-2_c.hci.aut-apo-ecc.p12`, `asforepa/src/test/resources/833621999741600-2_c.hci.aut-apo-rsa.p12` can be published and
were therefore added for unit tests.

## Usage

| Method | Endpoint                      | Request                                                                                                  | Response         | Validation                                                                                                                                                                                              |
|--------|-------------------------------|----------------------------------------------------------------------------------------------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | getNonce                      | header: </br> x-useragent                                                                                | body: nonce      | -                                                                                                                                                                                                       |
| GET    | send_authorization_request_sc | header: </br> x-useragent                                                                                | header: location | -                                                                                                                                                                                                       |
| POST   | send_authcode_sc              | header: </br> x-useragent </br> </br> body:<br/> AuthCodeRequest <br/> (conatins authCode, clientAttest) | body: vau-np     | *authCode:* <br/> + not null <br/> + all header claims correct <br/> - no validation of the claim value <br/> <br/> *clientAttest:* <br/> + not null <br/> + iat and exp </br> + checks algorithm value |

**getNonce**
> - PS requests a valid nonce
> - PS has to sign the nonce, which will be sent as clientattest in send_authcode_sc


**send_authorization_request_sc**
> - AS builds redirect-URI with different parameters and sets it as Location Header to direct to
    central IDP
> > - redirect_uri - client-Uri
> > - client_id
> > - state
> > - nonce
> > - code_challenge
> > - code_challenge_method
> > - scope
> > - response_type

**send_authcode_sc**
> - PS sends authCode (received by IDP) and clientAttest
> - AS validates both values for not being null
> - AS validates if authCode has correct claims, but doesn't check the claim value
> - AS checks if algorithm in client attest header is "ES256" or "PS256"

## OpenAPI Specification

You can receive the OpenAPI Specification under the following paths

| Format  | Path                                   |
|---------|----------------------------------------|
| JSON    | http://127.0.0.1:8086/v3/api-docs      |
| YAML    | http://127.0.0.1:8086/v3/api-docs.yaml |
| SWAGGER | http://127.0.0.1:8086/swagger-ui.html  |

### asforepa-server logging
Logs are written via log4j2 to console.

Export LOG_LEVEL_GEMATIK=\<YOUR LOG LEVEL> to set the log level.
Export REQUEST_LOGGING_ENABLED=false to disable request logging.
See also [ASFOREPA application.yml](asforepa/src/main/resources/application.yml) for configuration.

## License

Copyright 2024-2025 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
