###############################################################################
# ShieldOps — ACM Certificate (TLS)
#
# Provisions a wildcard ACM certificate for the apex domain and all
# subdomains, validated via Route53 DNS records. The certificate is wired
# into the ALB HTTPS listener (see alb.tf).
###############################################################################

# ---------------------------------------------------------------------------
# ACM Certificate — wildcard + apex
# ---------------------------------------------------------------------------

resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${local.name_prefix}-wildcard-cert"
    Environment = var.environment
    Service     = "shieldops"
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# DNS validation records — one per domain validation option
# ---------------------------------------------------------------------------

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# ---------------------------------------------------------------------------
# Certificate validation — blocks until ACM observes the DNS records
# ---------------------------------------------------------------------------

resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ---------------------------------------------------------------------------
# Locals — resolve the effective certificate ARN used by the ALB listener.
# If var.certificate_arn is set, it takes precedence (allows BYO cert).
# ---------------------------------------------------------------------------

locals {
  effective_certificate_arn = (
    var.certificate_arn != ""
    ? var.certificate_arn
    : aws_acm_certificate_validation.main.certificate_arn
  )
}
