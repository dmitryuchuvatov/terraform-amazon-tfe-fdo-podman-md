output "tfe_login" {
  description = "URL for TFE login"
  value       = "https://${var.route53_subdomain}.${var.route53_zone}"
}

output "ssh_login" {
  description = "SSH login command"
  value       = "ssh -i tfesshkey.pem ec2-user@${var.route53_subdomain}.${var.route53_zone}"
}