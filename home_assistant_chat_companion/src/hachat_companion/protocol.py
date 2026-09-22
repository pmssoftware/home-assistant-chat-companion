"""Wire-level constants shared by listeners and future clients."""

MESSAGE_PROTOCOL = "ha-chat/2"
CLIENT_PROTOCOL = "ha-chat-client/2"
FEDERATION_PROTOCOL = "ha-chat-federation/2"
CAPABILITIES = (
    "devices.p256.v1",
    "key-packages.opaque-reserved.v2",
    "direct-messages.opaque.v1",
    "receipts.explicit-delivered-read.v2",
)
API_VERSION = 2
STORAGE_SCHEMA_VERSION = 4

PROTOCOL_HEADER = "X-HA-Chat-Protocol"
CONTENT_TYPE = "application/json; charset=utf-8"

MAX_JSON_BODY = 96 * 1024
MAX_CIPHERTEXT_BYTES = 48 * 1024
MAX_INBOX_PAGE = 50
MAX_OUTBOX_ATTEMPTS = 10_000
MAX_ACCOUNT_EVENTS = 10_000
MAX_ACCOUNT_EVENT_BYTES = 64 * 1024 * 1024
MAX_OUTBOX_PER_PEER = 4
MESSAGE_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_IDENTITY_INPUT = 64
MAX_DISPLAY_NAME = 80
MAX_PASSWORD_BYTES = 1024
MAX_NONCE_LENGTH = 96
FEDERATION_CLOCK_SKEW_SECONDS = 300
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
