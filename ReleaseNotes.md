# Release 2.0.3

- update regex pattern for user agent validation
- update dependencies

# Release 2.0.2

- add custom AsEpaErrorResponse and AsEpaErrorCode
- bug fix in null value validation
- update dependencies

# Release 2.0.1

- bug fix in send_authcode_sc response
- add validation for client attest and auth code to be base64url
- update dependencies

# Release 2.0.0

- remove parent pom from testsuite to avoid dependency conflicts
- change user-agent name to "x-useragent"
- remove signature validation for client attest but check if algorithm is ES256 or PS256
- validate useragent against regex
- add session handling

# Release 1.0.3

- initial release
- minimal parameter validation
- no session handling
- no communication with idp
