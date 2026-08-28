#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
playground="$script_dir/aster-mesh-playground.sh"
network="${ASTER_HELLO_NETWORK:-}"
network_argument=0
network_value_pending=0

for hello_argument in "$@"; do
  if [ "$network_value_pending" -eq 1 ]; then
    network_argument=1
    network_value_pending=0
    continue
  fi
  case "$hello_argument" in
    --hello|--hello=*|--nodes|--nodes=*)
      echo "--hello and --nodes are hello-wrapper-managed options" >&2
      exit 2
      ;;
    --network)
      network_value_pending=1
      ;;
    --network=*)
      network_argument=1
      ;;
  esac
done

if [ "$network_value_pending" -eq 1 ]; then
  echo "--network requires nearby or invitation" >&2
  exit 2
fi

if [ "$network_argument" -eq 0 ]; then
  if [ -z "$network" ]; then
    if [ ! -t 0 ]; then
      echo "hello requires a human network choice: --network nearby or --network invitation" >&2
      exit 2
    fi
    printf '%s\n' "ASTER FIELD NOTES" >&2
    printf '%s\n' "How should this disposable three-node roster find its routes?" >&2
    printf '%s\n' "  1) nearby     short 10-second local-network locator windows" >&2
    printf '%s\n' "  2) invitation controller-known local routes (multicast not required)" >&2
    printf '%s' "Choose 1 or 2; there is no automatic fallback: " >&2
    IFS= read -r selection
    case "$selection" in
      1|nearby) network="nearby" ;;
      2|invitation) network="invitation" ;;
      *)
        echo "hello route choice must be 1/nearby or 2/invitation" >&2
        exit 2
        ;;
    esac
  fi
  case "$network" in
    nearby|invitation) ;;
    *)
      echo "ASTER_HELLO_NETWORK must be nearby or invitation" >&2
      exit 2
      ;;
  esac
  exec /bin/sh "$playground" --hello --nodes 3 --network "$network" "$@"
fi

exec /bin/sh "$playground" --hello --nodes 3 "$@"
