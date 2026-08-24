# Release Guide

This guide explains the step-by-step process for releasing a new version of the **jokoway** project. 

The project uses `just` to automate the release workflow, including updating dependencies, generating the changelog, and publishing Docker images to the GitHub Container Registry (GHCR).

## Prerequisites

- [just](https://github.com/casey/just) installed.
- [git-cliff](https://github.com/orhun/git-cliff) installed (used for changelog generation).
- Docker installed and authenticated with GHCR:
  ```bash
  export CR_PAT=YOUR_GITHUB_PERSONAL_ACCESS_TOKEN
  echo $CR_PAT | docker login ghcr.io -u <your-github-username> --password-stdin
  ```

---

## Release Steps

### 1. Update the Version
First, update the version of your crate(s) in `Cargo.toml`. Since this is a workspace with multiple crates, you should bump the version in the main crate, and then synchronize that version across any dependent crates in the workspace.

For example, after manually bumping the version of `jokoway-core` in `jokoway-core/Cargo.toml`, run:

```bash
just update-dependent jokoway-core
```
*(This will automatically update the version of `jokoway-core` in all other `Cargo.toml` files that depend on it).*

Next, ensure you also update the version label inside the `Dockerfile` to match the new version:
```dockerfile
LABEL org.opencontainers.image.version="X.Y.Z"
```

### 2. Generate the Changelog
We use `git-cliff` to automatically generate the changelog based on the commit history. The `Justfile` is configured to extract the current version directly from `jokoway/Cargo.toml` and apply it to the new changelog entries.

Generate or update the `CHANGELOG.md` by running:

```bash
just changelog
```

> **Note**: You can also use `just changelog-latest` if you only want to print the latest unreleased changes to the terminal.

### 3. Commit and Tag
Commit the version bumps and the updated `CHANGELOG.md`, then create a Git tag for the release.

```bash
git add .
git commit -m "chore(release): vX.Y.Z"
git tag -a vX.Y.Z -m "Release vX.Y.Z"
```
*(Replace `X.Y.Z` with your actual version number).*

### 4. Build and Publish Docker Images
Build the Docker images and push them to GHCR. 

If you want to build and push a **multi-platform** image (e.g., `linux/amd64` and `linux/arm64`) using Docker Buildx, run:
```bash
just build-push-image
```

If you only want to build and push for your **current architecture**, you can use:
```bash
just publish-image
```

### 5. Push to GitHub
Finally, push your commit and the new tag to the remote repository.

```bash
git push origin main --tags
```
