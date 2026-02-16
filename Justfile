version := `grep "^version" jokoway/Cargo.toml | head -1 | cut -d '"' -f 2`
image_name := "ghcr.io/hijriyan/jokoway"

# List available commands
default:
    @just --list

# Print current version
print-version:
    @echo {{version}}

# Build docker image
build-image:
    docker build -t {{image_name}}:{{version}} -t {{image_name}}:latest .
    docker build -f Dockerfile.alpine -t {{image_name}}:{{version}}-alpine -t {{image_name}}:alpine .

# Push docker image to GHCR
push-image:
    docker push {{image_name}}:{{version}}
    docker push {{image_name}}:latest
    docker push {{image_name}}:{{version}}-alpine
    docker push {{image_name}}:alpine

# Build and push docker image to GHCR
publish-image: build-image push-image

# Update version of a workspace crate in all dependent Cargo.toml files
# Usage: just update-dependent <crate>            # update versions
#        just update-dependent <crate> --dry-run   # only show hierarchy
update-dependent crate +args="":
    #!/usr/bin/env bash
    set -euo pipefail

    dry_run=false
    for arg in {{args}}; do
        if [ "$arg" = "--dry-run" ]; then
            dry_run=true
        fi
    done

    # Get the version from the crate's Cargo.toml
    crate_version=$(grep '^version' "{{crate}}/Cargo.toml" | head -1 | cut -d '"' -f 2)
    if [ -z "$crate_version" ]; then
        echo "Error: Could not find version for crate '{{crate}}'"
        exit 1
    fi
    echo "📦 {{crate}} v$crate_version"

    # Find all workspace member Cargo.toml files that depend on this crate (excluding the crate itself)
    updated=0
    for toml in */Cargo.toml; do
        dir=$(dirname "$toml")
        # Skip the crate's own Cargo.toml
        if [ "$dir" = "{{crate}}" ]; then
            continue
        fi
        # Check if this Cargo.toml depends on the crate
        if grep -q '{{crate}}' "$toml"; then
            current=$(grep '{{crate}}' "$toml" | grep -oE 'version = "[^"]+"' | head -1 | cut -d '"' -f 2)
            if [ "$dry_run" = true ]; then
                echo "└── $dir (current: v${current:-unknown})"
            else
                echo "Updating $toml (v${current:-unknown} → v$crate_version) ..."
                sed -i '' -E '/{{crate}}/s/version = "[^"]+"/version = "'"$crate_version"'"/' "$toml"
            fi
            updated=$((updated + 1))
        fi
    done

    if [ "$updated" -eq 0 ]; then
        echo "No dependents found for '{{crate}}'"
    elif [ "$dry_run" = true ]; then
        echo ""
        echo "$updated dependent(s) found (dry-run, no changes made)"
    else
        echo "Updated $updated Cargo.toml file(s) to version $crate_version"
    fi
