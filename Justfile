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
