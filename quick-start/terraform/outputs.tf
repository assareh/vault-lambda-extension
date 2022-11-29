output "info" {
  value = <<EOF

Vault Server IP (public): ${aws_instance.vault-server.public_ip}
Vault UI URL:             https://${aws_instance.vault-server.public_ip}:8200/ui

You can SSH into the Vault EC2 instance using private.key:
    ssh -i private.key ubuntu@${aws_instance.vault-server.public_ip}

EOF
}

output "vault_addr" {
  value = "https://${aws_instance.vault-server.public_ip}:8200"
}

output "ssh_private_key" {
value = nonsensitive(tls_private_key.main.private_key_pem)
}