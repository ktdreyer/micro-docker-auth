micro-docker-auth
=================

Tiny Flask-based webservice that implements the Docker token server API.

This server is very bare-bones. I needed something to protect a public Docker
registry that was Python-based and straightforward to maintain and secure.

- Gives out tokens for "pull" access to all repos for anyone, no password
  required. This means anonymous users can ``docker pull`` from any repository.

- All other actions require a username and password. In other words,
  ``docker push`` requires authentication.

- There is only one username ("admin") and password.
