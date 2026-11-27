# Shared setup for the test scripts. Source it, don't run it.
#
# wq_copy_src <project-dir> <dest-dir>
#   Copies only the project files the tests run from. Game libraries, logs, prefixes, probe
#   folders and third_party rule sets are left out, so a test can't fill /tmp, and a copy of
#   someone's home folder is refused outright.
wq_copy_src() {
  local src="$1" dst="$2" real_src real_home
  real_src="$(readlink -f "$src")"
  real_home="$(readlink -f "${HOME:-/nonexistent}")"
  case "$real_src" in
    "$real_home"|/|/home|/root|/home/*/)
      echo "test: refusing to copy '$real_src' (that is a home folder). Run the tests from the project folder." >&2
      exit 2 ;;
  esac
  if [ ! -f "$real_src/wq-ui/test_core.py" ]; then
    echo "test: '$real_src' does not look like the wine-quarantine folder (wq-ui/test_core.py is missing)." >&2
    exit 2
  fi
  (cd "$real_src" && tar -c \
      --exclude=.git --exclude=third_party --exclude=docs --exclude=__pycache__ \
      --exclude=logs --exclude='_sandbox-test' --exclude='probev2*' --exclude='*.yarc' \
      .) | (cd "$dst" && tar -x)
}
