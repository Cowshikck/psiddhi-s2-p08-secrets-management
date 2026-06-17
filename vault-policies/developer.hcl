# Developer policy - read-only access to dev secrets
path "secret/data/db-credentials/*" {
  capabilities = ["read", "list"]
}
path "secret/data/api-keys/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}