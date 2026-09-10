from prometheus_client import Counter

AUTHENTICATIONS = Counter(
    "identity_gateway_authentications_total",
    "Access-token authentication results",
    ["outcome"],
)
AUTHORIZATIONS = Counter(
    "identity_gateway_authorizations_total",
    "Authorization policy decisions",
    ["policy", "outcome"],
)
UPSTREAM_REQUESTS = Counter(
    "identity_gateway_upstream_requests_total",
    "Protected-service request results",
    ["outcome"],
)
