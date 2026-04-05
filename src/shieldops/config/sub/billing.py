"""Billing configuration."""

from pydantic import BaseModel


class BillingConfig(BaseModel):
    """Stripe, GCP, and Azure billing settings."""

    # Stripe
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_api_key: str = ""
    stripe_success_url: str = "http://localhost:5173/settings?billing=success"
    stripe_cancel_url: str = "http://localhost:5173/settings?billing=cancel"
    stripe_price_starter: str = ""
    stripe_price_professional: str = ""
    stripe_price_enterprise: str = ""

    # GCP Billing
    gcp_billing_dataset: str = "billing_export"
    gcp_billing_table: str = "gcp_billing_export_v1"

    # Azure Billing
    azure_billing_enabled: bool = False
