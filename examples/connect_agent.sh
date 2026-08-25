#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 CLIENT_TOKEN_FILE" >&2
  exit 2
fi

ASTER_CLIENT_TOKEN="$(tr -d '\r\n' < "$1")"
ASTER_AGENT_URL="http://127.0.0.1:8181"

rpc() {
  method="$1"
  data="$2"
  mise exec -- buf curl --schema . --reflect=false \
    -H "Authorization: Bearer $ASTER_CLIENT_TOKEN" \
    -d "$data" \
    "$ASTER_AGENT_URL/aster.application.v1alpha1.AsterApplicationService/$method"
}

rpc GetStatus '{}'
subscription="$(rpc CreateEventSubscription \
  '{"operationKey":"Y29ubmVjdC1xdWlja3N0YXJ0LXN1YnNjcmlwdGlvbg==","topic":"chat.events","scope":"mission/team/alpha"}')"
subscription_id="$(printf '%s' "$subscription" | jq -r .subscriptionId)"

rpc PublishEvent \
  '{"operationKey":"Y29ubmVjdC1xdWlja3N0YXJ0LXB1YmxpY2F0aW9u","topic":"chat.events","scope":"mission/team/alpha","priority":"PRIORITY_ROUTINE","logicalKey":"YXNzZXQtNw==","payload":"cmVhZHk="}'
page="$(rpc PollEvents \
  "{\"subscriptionId\":\"$subscription_id\",\"deliveryLimit\":8,\"scanLimit\":32}")"
printf '%s\n' "$page"
event_id="$(printf '%s' "$page" | jq -r '.deliveries[0].event.id // empty')"
if [ -n "$event_id" ]; then
  rpc AcknowledgeEvent \
    "{\"subscriptionId\":\"$subscription_id\",\"eventId\":\"$event_id\"}"
fi
