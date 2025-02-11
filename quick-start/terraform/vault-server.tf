//--------------------------------------------------------------------
// Vault Server Instance

resource "aws_instance" "vault-server" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids      = [aws_security_group.vault-server.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.vault-server.id
  subnet_id                   = var.subnet_id

  tags = {
    Name = "${var.environment_name}-vault-server"
  }

  user_data = templatefile(
    "${path.module}/templates/userdata-vault-server.tpl",
    {
      tpl_vault_zip_file     = var.vault_zip_file
      tpl_vault_service_name = "vault"
      tpl_kms_key            = aws_kms_key.vault.id
      tpl_aws_region         = var.aws_region
      tpl_account_id         = data.aws_caller_identity.current.account_id
      tpl_organization       = var.organization
      tpl_workspace          = var.workspace
  })

  # Bit of a hack to wait for user_data script to finish running before returning
  provisioner "remote-exec" {
    inline = [
      "while [ ! -f /tmp/user-data-completed ]; do sleep 2; done",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = aws_instance.vault-server.public_ip
      private_key = tls_private_key.main.private_key_pem
    }
  }

  lifecycle {
    ignore_changes = [
      ami,
      tags,
    ]
  }
}

data "aws_caller_identity" "current" {
}