variable "region" {
  type        = string
  description = "The region to deploy resources in"
}

variable "environment_name" {
  type        = string
  description = "Name used to create and tag resources"
}

variable "vpc_cidr" {
  type        = string
  description = "The IP range for the VPC in CIDR format"
}

variable "route53_zone" {
  description = "The domain used in the URL"
  type        = string
}

variable "route53_subdomain" {
  description = "The subdomain of the URL"
  type        = string
}

variable "cert_email" {
  description = "Email address used to obtain SSL certificate"
  type        = string
}

variable "tfe_release" {
  description = "TFE release version (https://developer.hashicorp.com/terraform/enterprise/releases)"
  type        = string
}

variable "tfe_password" {
  description = "TFE encryption password"
  type        = string
}

variable "tfe_license" {
  description = "TFE license value"
  type        = string
}

