matrixtoken
===========

[![build][build-svg]][build-url] [![coverage][cover-svg]][cover-url]

The Client-Server [Matrix] protocol allows to limit registrations based on
[tokens], [Synapse] (and other Matrix servers) [support] this feature and
have an admin API to [manage] these tokens.

matrixtoken is a tool that allows users of the system to generate Matrix
registration tokens from the homeserver admin API, without being admins
themselves.

It is supposed to be used with the SUID mode to allow it to read its config
file containing the admin's access token.

After it has been installed and configured, users can simply run:

    matrixtoken

Which will return a token with a limited amount of uses and an expiration
date (by default 1 use and 30 days of validity).

[Matrix]: https://matrix.org/
[tokens]: https://spec.matrix.org/unstable/client-server-api/#token-authenticated-registration
[Synapse]: https://github.com/element-hq/synapse/
[support]: https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html#registration_requires_token
[manage]: https://element-hq.github.io/synapse/latest/usage/administration/admin_api/registration_tokens.html

[build-svg]: https://github.com/club-1/matrixtoken/actions/workflows/build.yml/badge.svg
[build-url]: https://github.com/club-1/matrixtoken/actions/workflows/build.yml
[cover-svg]: https://github.com/club-1/matrixtoken/wiki/coverage.svg
[cover-url]: https://raw.githack.com/wiki/club-1/matrixtoken/coverage.html
