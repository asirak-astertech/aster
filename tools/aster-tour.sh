#!/bin/sh

set -eu

tour_mode="${1:-quick}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
aster_bin="${ASTER_TOUR_BIN:-}"

if [ -n "${ASTER_TOUR_PARENT:-}" ]; then
  tour_parent="$ASTER_TOUR_PARENT"
  mkdir -p "$tour_parent"
else
  tour_tmp_root="${TMPDIR:-/tmp}"
  tour_parent="$(mktemp -d "${tour_tmp_root%/}/aster-tour.XXXXXX")"
fi

if [ -e "$tour_parent/cargo-build.json" ] || \
  [ -e "$tour_parent/aster-bin.path" ]; then
  echo "tour parent already contains a retained run: $tour_parent" >&2
  exit 2
fi

if [ -z "${ASTER_TOUR_BIN:-}" ]; then
  echo "Building the Aster CLI for this checkout..."
  build_receipt="$tour_parent/cargo-build.json"
  cargo build --locked --manifest-path "$repo_root/Cargo.toml" \
    -p aster-node --bin aster --message-format=json >"$build_receipt"
  aster_bin="$(python3 -c 'import json, sys; objects = (json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()); paths = [obj["executable"] for obj in objects if obj.get("reason") == "compiler-artifact" and obj.get("executable") and obj.get("target", {}).get("name") == "aster" and "bin" in obj.get("target", {}).get("kind", [])]; print(paths[-1])' "$build_receipt")"
fi

if [ ! -x "$aster_bin" ]; then
  echo "ASTER_TOUR_BIN is not executable: $aster_bin" >&2
  exit 2
fi
aster_bin_dir="$(CDPATH= cd -- "$(dirname -- "$aster_bin")" && pwd)"
aster_bin="$aster_bin_dir/$(basename -- "$aster_bin")"
printf '%s\n' "$aster_bin" >"$tour_parent/aster-bin.path"

run_tour() {
  name="$1"
  nodes="$2"
  scenario="$3"
  base_port="$4"
  root="$tour_parent/$name"
  demo_stdout="$tour_parent/$name.demo.stdout"
  demo_stderr="$tour_parent/$name.demo.stderr"
  inspect_stdout="$tour_parent/$name.inspect.stdout"
  inspect_stderr="$tour_parent/$name.inspect.stderr"

  if [ -e "$root" ] || [ -e "$demo_stdout" ] || [ -e "$demo_stderr" ] || \
    [ -e "$inspect_stdout" ] || [ -e "$inspect_stderr" ]; then
    echo "refusing to overwrite retained tour evidence under: $tour_parent" >&2
    return 2
  fi

  echo
  echo "==> Aster $name tour ($nodes nodes)"
  if [ -n "$base_port" ]; then
    echo "Using explicit base port: $base_port"
  fi

  demo_command() {
    if [ "$scenario" = "default" ]; then
      if [ -n "$base_port" ]; then
        "$aster_bin" demo --nodes "$nodes" --root "$root" \
          --base-port "$base_port"
      else
        "$aster_bin" demo --nodes "$nodes" --root "$root"
      fi
    elif [ -n "$base_port" ]; then
      "$aster_bin" demo --nodes "$nodes" --scenario "$scenario" \
        --root "$root" --base-port "$base_port"
    else
      "$aster_bin" demo --nodes "$nodes" --scenario "$scenario" --root "$root"
    fi
  }

  if demo_command >"$demo_stdout" 2>"$demo_stderr"; then
    :
  else
    demo_status=$?
    cat "$demo_stdout"
    cat "$demo_stderr" >&2
    return "$demo_status"
  fi
  cat "$demo_stdout"
  if [ -s "$demo_stderr" ]; then
    cat "$demo_stderr" >&2
  fi

  : >"$inspect_stdout"
  : >"$inspect_stderr"
  node=0
  while [ "$node" -lt "$nodes" ]; do
    if "$aster_bin" inspect --state "$root/node-$node" \
      >>"$inspect_stdout" 2>>"$inspect_stderr"; then
      :
    else
      inspect_status=$?
      cat "$inspect_stdout"
      cat "$inspect_stderr" >&2
      return "$inspect_status"
    fi
    node=$((node + 1))
  done
  cat "$inspect_stdout"
  if [ -s "$inspect_stderr" ]; then
    cat "$inspect_stderr" >&2
  fi

  echo "Artifacts retained at: $root"
  echo "Parent receipt:        $demo_stdout"
  echo "Inspection receipt:    $inspect_stdout"
  echo "Application receipts:  rg '^APPLICATION ' '$root/logs'"
  echo "Contact receipts:      rg '^CONTACT ' '$root/logs'"
}

requested_base_port="${ASTER_TOUR_BASE_PORT:-}"

case "$tour_mode" in
  quick)
    run_tour quick 2 default "$requested_base_port"
    ;;
  relay)
    run_tour relay 3 default "$requested_base_port"
    ;;
  control)
    run_tour control 4 control "$requested_base_port"
    ;;
  all)
    if [ -n "$requested_base_port" ]; then
      run_tour quick 2 default "$requested_base_port"
      run_tour relay 3 default "$((requested_base_port + 100))"
      run_tour control 4 control "$((requested_base_port + 200))"
    else
      run_tour quick 2 default ""
      run_tour relay 3 default ""
      run_tour control 4 control ""
    fi
    ;;
  *)
    echo "usage: sh tools/aster-tour.sh [quick|relay|control|all]" >&2
    exit 2
    ;;
esac
