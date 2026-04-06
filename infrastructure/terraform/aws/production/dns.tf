###############################################################################
# ShieldOps — Route53 DNS
#
# Manages public DNS records for the ShieldOps control plane:
#   - api.<domain>    → ALB (A alias)
#   - app.<domain>    → ALB (A alias)
#   - status.<domain> → external status page provider (CNAME)
#
# The hosted zone is assumed to pre-exist (registered/delegated out-of-band)
# and is resolved via a data source.
###############################################################################

# ---------------------------------------------------------------------------
# Hosted zone (data source — assumed to pre-exist)
# ---------------------------------------------------------------------------

data "aws_route53_zone" "main" {
  name         = var.domain_name
  private_zone = false
}

# ---------------------------------------------------------------------------
# A record — api.<domain> → ALB
# ---------------------------------------------------------------------------

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.subdomain_api}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# ---------------------------------------------------------------------------
# A record — app.<domain> → ALB
# ---------------------------------------------------------------------------

resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.subdomain_app}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# ---------------------------------------------------------------------------
# CNAME — status.<domain> → external status page provider
#
# External dependency: the status page is hosted by a third-party SaaS
# (e.g. statuspage.io, Atlassian Statuspage, BetterStack, Instatus).
# Update `var.status_page_target` once the vendor-issued CNAME target is
# known. See status_page.tf for the alerting integration.
# ---------------------------------------------------------------------------

resource "aws_route53_record" "status" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.subdomain_status}.${var.domain_name}"
  type    = "CNAME"
  ttl     = 300
  records = [var.status_page_target]
}
