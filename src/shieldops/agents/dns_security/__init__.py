"""DNS Security Agent — DNS monitoring for tunneling, DGA detection, and typosquatting."""

from .graph import create_dns_security_graph

__all__ = ["create_dns_security_graph"]
