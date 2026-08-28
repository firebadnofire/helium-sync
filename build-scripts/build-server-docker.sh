#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
dockerfile="$repo_root/docker/Dockerfile"
image_tag="${HELIUM_SYNC_DOCKER_TAG:-helium-sync-server:local}"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "Docker is required and was not found in PATH."
[[ -f "$dockerfile" ]] || fail "Dockerfile not found: $dockerfile"
docker info >/dev/null 2>&1 || fail "The Docker daemon is unavailable or the current user cannot access it."

printf 'Building Docker image %s from %s\n' "$image_tag" "$dockerfile"
docker build --file "$dockerfile" --tag "$image_tag" "$repo_root"

image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
[[ -n "$image_id" ]] || fail "Docker reported success, but image $image_tag could not be inspected."
printf 'Built %s (%s)\n' "$image_tag" "$image_id"
