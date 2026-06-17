# Platform admin policy - full control on all secret paths
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list", "delete"]
}
path "sys/audit/*" {
  capabilities = ["read", "list", "sudo"]
}
path "sys/policies/*" {
  capabilities = ["read", "list"]
}