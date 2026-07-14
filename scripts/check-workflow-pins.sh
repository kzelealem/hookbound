#!/usr/bin/env bash
set -euo pipefail

status=0
while IFS= read -r match; do
  location="${match%%:*}"
  remainder="${match#*:}"
  line_number="${remainder%%:*}"
  content="${remainder#*:}"
  reference="$(sed -E 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*/\1/' <<<"$content")"
  case "$reference" in
    ./*)
      continue
      ;;
  esac
  version="${reference##*@}"
  if [[ "$reference" = "$version" || ${#version} -ne 40 || "$version" =~ [^0-9a-f] ]]; then
    printf '%s:%s: action must be pinned to a full lowercase commit SHA: %s\n' \
      "$location" "$line_number" "$reference" >&2
    status=1
  fi
done < <(grep -R -n -E '^[[:space:]]*uses:[[:space:]]*' .github/workflows --include='*.yml' --include='*.yaml' || true)

exit "$status"
