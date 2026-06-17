# CI/CD service principal policy - read access to dev + staging secrets
path "secret/data/db-credentials/*" {
  capabilities = ["read", "list"]
}
path "secret/data/api-keys/*" {
  capabilities = ["read", "list"]
}
path "secret/data/service-tokens/*" {
  capabilities = ["read", "list"]
}
path "secret/data/env-config/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}