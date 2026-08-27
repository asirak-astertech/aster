#!/bin/sh

set -eu

tour_mode="${1:-quick}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
tour_view="$script_dir/aster_tour_ui.py"
tour_view_mode="${ASTER_TOUR_VIEW:-auto}"
aster_bin="${ASTER_TOUR_BIN:-}"

case "$tour_view_mode" in
  auto|tui|plain|raw) ;;
  *)
    echo "ASTER_TOUR_VIEW must be one of: auto, tui, plain, raw" >&2
    exit 2
    ;;
esac

if [ -n "${ASTER_TOUR_PARENT:-}" ]; then
  tour_parent="$ASTER_TOUR_PARENT"
  mkdir -p "$tour_parent"
else
  tour_tmp_root="${TMPDIR:-/tmp}"
  tour_parent="$(mktemp -d "${tour_tmp_root%/}/aster-tour.XXXXXX")"
fi

if [ -e "$tour_parent/cargo-build.json" ] || \
  [ -e "$tour_parent/cargo-build.stderr" ] || \
  [ -e "$tour_parent/aster-bin.path" ]; then
  echo "tour parent already contains a retained run: $tour_parent" >&2
  exit 2
fi

if [ ! -r "$tour_view" ]; then
  echo "tour presenter is not readable: $tour_view" >&2
  exit 2
fi

active_presenter_pid=""
presenter_signal_pending=0
presenter_signal_status=0

forward_presenter_signal() {
  presenter_signal_name="$1"
  presenter_signal_status="$2"
  presenter_signal_pending=1
  if [ -n "$active_presenter_pid" ]; then
    kill -s "$presenter_signal_name" "$active_presenter_pid" 2>/dev/null || :
  fi
}

run_presenter() {
  active_presenter_pid=""
  presenter_signal_pending=0
  presenter_signal_status=0
  # TERM is not inherited as ignored by asynchronous POSIX-shell children, so
  # use it to carry an early Ctrl-C safely until the presenter installs traps.
  trap 'forward_presenter_signal TERM 130' INT
  trap 'forward_presenter_signal TERM 143' TERM
  trap 'forward_presenter_signal HUP 129' HUP

  "$@" &
  active_presenter_pid=$!
  if [ "$presenter_signal_pending" -eq 1 ]; then
    kill -s "$presenter_signal_name" "$active_presenter_pid" 2>/dev/null || :
  fi

  while :; do
    if wait "$active_presenter_pid"; then
      presenter_status=0
    else
      presenter_status=$?
    fi
    if [ "$presenter_signal_pending" -eq 1 ]; then
      presenter_signal_pending=0
      if kill -0 "$active_presenter_pid" 2>/dev/null; then
        continue
      fi
    fi
    break
  done

  active_presenter_pid=""
  trap - INT TERM HUP
  if [ "$presenter_signal_status" -ne 0 ]; then
    presenter_status="$presenter_signal_status"
  fi
  return "$presenter_status"
}

if [ -z "${ASTER_TOUR_BIN:-}" ]; then
  build_receipt="$tour_parent/cargo-build.json"
  build_stderr="$tour_parent/cargo-build.stderr"
  if run_presenter python3 "$tour_view" build \
    --view "$tour_view_mode" \
    --stdout-receipt "$build_receipt" \
    --stderr-receipt "$build_stderr" -- \
    cargo build --locked --manifest-path "$repo_root/Cargo.toml" \
      -p aster-node --bin aster --message-format=json; then
    :
  else
    build_status=$?
    echo "Build receipts retained under: $tour_parent" >&2
    exit "$build_status"
  fi
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

  if [ "$tour_view_mode" != "raw" ]; then
    echo
    echo "Aster $name tour ($nodes independent nodes)"
    if [ -n "$base_port" ]; then
      echo "  Explicit loopback port block starts at $base_port"
    fi
  fi

  show_artifacts() {
    if [ "$tour_view_mode" = "raw" ]; then
      if python3 "$tour_view" artifacts --root "$root" \
        --demo-receipt "$demo_stdout" --inspect-receipt "$inspect_stdout" >&2; then
        :
      else
        echo "warning: could not present retained artifact locations" >&2
      fi
    else
      if python3 "$tour_view" artifacts --root "$root" \
        --demo-receipt "$demo_stdout" --inspect-receipt "$inspect_stdout"; then
        :
      else
        echo "warning: could not present retained artifact locations" >&2
      fi
    fi
  }

  demo_command() {
    if [ "$scenario" = "default" ]; then
      if [ -n "$base_port" ]; then
        run_presenter python3 "$tour_view" demo --tour "$name" --nodes "$nodes" \
          --demo-root "$root" --view "$tour_view_mode" \
          --stdout-receipt "$demo_stdout" --stderr-receipt "$demo_stderr" -- \
          "$aster_bin" demo --nodes "$nodes" --root "$root" \
            --base-port "$base_port"
      else
        run_presenter python3 "$tour_view" demo --tour "$name" --nodes "$nodes" \
          --demo-root "$root" --view "$tour_view_mode" \
          --stdout-receipt "$demo_stdout" --stderr-receipt "$demo_stderr" -- \
          "$aster_bin" demo --nodes "$nodes" --root "$root"
      fi
    elif [ -n "$base_port" ]; then
      run_presenter python3 "$tour_view" demo --tour "$name" --nodes "$nodes" \
        --demo-root "$root" --view "$tour_view_mode" \
        --stdout-receipt "$demo_stdout" --stderr-receipt "$demo_stderr" -- \
        "$aster_bin" demo --nodes "$nodes" --scenario "$scenario" \
          --root "$root" --base-port "$base_port"
    else
      run_presenter python3 "$tour_view" demo --tour "$name" --nodes "$nodes" \
        --demo-root "$root" --view "$tour_view_mode" \
        --stdout-receipt "$demo_stdout" --stderr-receipt "$demo_stderr" -- \
        "$aster_bin" demo --nodes "$nodes" --scenario "$scenario" --root "$root"
    fi
  }

  if demo_command; then
    :
  else
    demo_status=$?
    show_artifacts
    return "$demo_status"
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
      if ! cat "$inspect_stdout"; then
        echo "warning: could not display partial inspection receipt" >&2
      fi
      if ! cat "$inspect_stderr" >&2; then
        echo "warning: could not display inspection stderr" >&2
      fi
      show_artifacts
      return "$inspect_status"
    fi
    node=$((node + 1))
  done
  if python3 "$tour_view" inspect --tour "$name" --nodes "$nodes" \
    --view "$tour_view_mode" --receipt "$inspect_stdout"; then
    :
  else
    echo "warning: could not present retained inspection receipt" >&2
  fi
  if [ -s "$inspect_stderr" ]; then
    if ! cat "$inspect_stderr" >&2; then
      echo "warning: could not display inspection stderr" >&2
    fi
  fi

  show_artifacts
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
