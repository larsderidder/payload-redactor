#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v python >/dev/null 2>&1; then
  echo "Python is required" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Git is required" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree is dirty; commit or stash before releasing" >&2
  exit 1
fi

version="$(python scripts/get_version.py)"

if [ -z "$version" ]; then
  echo "Could not determine version from pyproject.toml" >&2
  exit 1
fi

tag="v${version}"
if git rev-parse "$tag" >/dev/null 2>&1; then
  echo "Git tag $tag already exists" >&2
  exit 1
fi

skip_confirm=false
if [[ "${1:-}" == "--yes" ]]; then
  skip_confirm=true
fi

echo "About to release ${tag}."
echo "This will tag ${tag} and push. GitHub Actions will build and publish to PyPI."
if [ "$skip_confirm" = false ]; then
  read -r -p "Continue? [y/N] " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Release aborted."
    exit 1
  fi
fi

git tag "$tag"
git push origin main --tags

echo "Tagged ${tag} and pushed. Watch the publish workflow at:"
echo "  https://github.com/larsderidder/payload-redactor/actions"
