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

### build project and run unit tests (skip integration tests == skip testsuite execution)

`mvn clean test -Dskip.inttests`

### build project and run integration tests

`mvn clean verify`

The key `asforepa/src/test/resources/833621999741600-2_c.hci.aut-apo-ecc.p12` can be published and
was
therefore added for unit tests.

## Usage

| Method | Endpoint                      | Request                                                            | Response         | Validation                                                                                                                                                                       |
|--------|-------------------------------|--------------------------------------------------------------------|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | getNonce                      | -                                                                  | body: nonce      | -                                                                                                                                                                                |
| GET    | send_authorization_request_sc | -                                                                  | header: location | -                                                                                                                                                                                |
| POST   | send_authcode_sc              | body:<br/> AuthCodeRequest <br/> (conatins authCode, clientAttest) | body: vau-np     | *authCode:* <br/> + not null <br/> + all header claims correct <br/> - no validation of the claim value <br/> <br/> *clientAttest:* <br/> + not null <br/> + verifies certificat |

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
> - AS validates the signature of the certificate/clientAttest, but doesn't check if the nonce is
    valid.