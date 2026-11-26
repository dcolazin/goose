---
title: goose in Docker
sidebar_label: goose in Docker
description: Run goose inside Docker containers, run extensions in existing containers for devcontainer workflows, and understand the security model of each approach
---

This guide covers two Docker-related scenarios:
1. **Running goose inside Docker** - Build and run the goose process itself in a container
2. **Running extensions in Docker** - Run goose on your host but execute extensions inside a container

A third, related option is the [Container Use MCP](/docs/mcp/container-use-mcp) extension, which creates disposable, isolated development environments on demand.

These approaches look similar, but they sit at different points on the confinement spectrum. See [Security Models](#security-models) to understand what each one does — and does not — protect against.

## Security Models

The key principle for comparing these options: **a security boundary is something the agent cannot decline.** A capability that the agent may choose to use is not a boundary.

| Approach | What runs in a container | What stays on your host | Protection level |
|---|---|---|---|
| goose in Docker | The goose process, all extensions, and every tool it can call | Only the container runtime and the paths you mount | **Process-level confinement** (strongest) |
| `--container` flag | Extensions and tools, including built-ins when goose is installed in the container | The goose process itself: config, sessions, and the model connection | **Tool-level confinement** (middle) |
| [Container Use MCP](/docs/mcp/container-use-mcp) | Disposable environments the agent creates per task | goose and all of its built-in tools, running with your permissions | **Isolated workspace, not a boundary** (agent opts in) |

### goose in Docker — process-level confinement

The entire goose process — the model connection, extensions, and every tool goose can call — lives inside the container. Even a prompt-injected or misbehaving agent can only act within the container filesystem, the paths you bind-mount, and the network you allow.

What this model does *not* protect:
- **Directories you mount read-write.** The project directory is the work surface, so changes there are possible by design.
- **Exfiltration of project files** if the container has outbound internet access.

Practical rules for keeping the boundary intact:
- Never mount the Docker socket (`docker.sock`) into the container, and never run `--privileged`. Either one is effectively an escape hatch.
- Any secret you pass into the container (such as an API key as an environment variable) becomes readable by the agent process. Pass only what the task needs.
- For a stronger boundary, consider hardened runtimes such as rootless Podman or gVisor's `runsc` runtime.

### `--container` — tool-level confinement

goose itself runs on your host, and the extensions from your `config.yaml` — including built-ins, when goose is installed inside the container — execute inside the specified container. The agent's *actions* happen in the container, but the goose process that routes them stays outside: it still reads your goose config, stores sessions on your host, and holds the model connection.

The enforcement point is goose's extension routing: anything the agent can reach outside that channel is not covered. This model fits devcontainer-style workflows where you want the tools and their environment contained while goose stays on the host.

### Container Use MCP — an isolated workspace, not a security boundary

Container Use adds tools that spin up disposable environments (git branches plus containers) for a task. It is excellent for reproducibility and for keeping experiment changes off your working tree.

However, goose and its built-in Developer tools (shell, text editor) still run on your host with your permissions. The agent *chooses* to work in the isolated environment — a prompt-injected or misbehaving agent can simply use its host-side tools instead. In short: this protects your working tree from the *task's* changes; it does not protect your host from the *agent*. You can tighten host-side tools with [tool permissions](/docs/guides/managing-tools/tool-permissions), but that is policy enforced inside the goose process, not a kernel boundary.

:::tip Combining the models
Container Use needs access to a Docker daemon to create environments. Running it inside a "goose in Docker" setup typically means mounting the Docker socket — which is itself an escape hatch (see above). Use Container Use as a complement for isolated development work, not as a layer stacked inside the confinement models.
:::

### Choosing a model

- You don't fully trust the task, the prompt source, or the model output → **goose in Docker**.
- You want contained tools and environments, but host-side goose config and sessions → **`--container`**.
- You want disposable, reproducible environments for cooperative tasks → **Container Use MCP**.

## Running goose Inside Docker

You can build goose from the source file within a Docker container. This approach not only provides security benefits by creating an isolated environment but also enhances consistency and portability. For example, if you need to troubleshoot an error on a platform you don't usually work with (such as Ubuntu), you can easily debug it using Docker.

To begin, you will need to modify the [`Dockerfile` and `docker-compose.yml` files](https://github.com/aaif-goose/goose/tree/main/documentation/docs/docker) to suit your requirements. Some changes you might consider include:

- **Required:** Setting your API key, provider, and model in the `docker-compose.yml` file as environment variables because the keyring settings do not work on Ubuntu in Docker. This example uses Google Gemini.

- **Optional:** Changing the base image to a different Linux distribution in the `Dockerfile`. This example uses Ubuntu, but you can switch to another distribution such as CentOS, Fedora, or Alpine.

- **Optional:** Mounting your personal goose settings and hints files in the `docker-compose.yml` file. This allows you to use your personal settings and hints files within the Docker container.

:::tip Automated Alternative
For an automated approach to creating isolated development environments, see the [Container-Use MCP extension](/docs/mcp/container-use-mcp), which creates and manages containers for you through conversation. Note that this is a different security model — see [Security Models](#security-models).
:::

After setting the credentials, you can build the Docker image using the following command:

```bash
docker-compose -f documentation/docs/docker/docker-compose.yml build
```

Next, run the container and connect to it using the following command:

```bash
docker-compose -f documentation/docs/docker/docker-compose.yml run --rm goose-cli
```

Inside the container, run the following command to configure goose:

```bash
goose configure
```

When prompted to save the API key to the keyring, select `No`, as you are already passing the API key as an environment variable.

Configure goose a second time, and this time, you can [add any extensions](/docs/getting-started/using-extensions) you need.

After that, you can start a session:

```bash
goose session
```

You should now be able to connect to goose with your configured extensions enabled.

## Running Extensions in Docker Containers

The `--container` flag allows you to run goose extensions inside your Docker containers.

### Usage

```bash
goose session --container <container-id-or-name>
```

Extensions configured in your `config.yaml` will automatically run inside the specified container. Find your container ID or name with `docker ps`.

### Requirements

- Extensions must exist in the container and be accessible via the same paths used in your extension config
- To run built-in extensions, the goose CLI must be [installed](/docs/getting-started/installation) inside the container

### Examples

```bash
# Start an interactive session with extensions from config.yaml
goose session --container my-dev-container

# Start a non-interactive session with instructions
goose run --container my-dev-container --text "your instructions here"

# Specify an extension to run in the container
goose session --container 4c76a1beed85 --with-extension "uvx mcp-server-fetch"

# Workaround: Use full path if container can't find the command
goose session --container 4c76a1beed85 --with-extension "/root/.local/bin/uvx mcp-server-fetch"
```
