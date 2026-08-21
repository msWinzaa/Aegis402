# Deployment Security

Production deployments should terminate TLS at Aegis or a validated reverse proxy, validate upstream certificates, restrict node-key file permissions to `0600`, and use an external secret manager or HSM-backed signing provider.

The application exposes interfaces for environment secrets, development file secrets, external secret managers and signing/key lifecycle providers. Consumer wallet keys are outside these interfaces.

Production startup validation can require TLS and an acknowledged external secret provider. An operator may explicitly opt into a weaker configuration for controlled environments.

Do not put consumer wallet keys or seed phrases in environment variables, SQLite, logs or Aegis configuration.
