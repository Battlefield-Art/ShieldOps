"""Kafka configuration."""

from pydantic import BaseModel


class KafkaConfig(BaseModel):
    """Kafka broker settings."""

    kafka_brokers: str = "localhost:9092"
    kafka_consumer_group: str = "shieldops-agents"
