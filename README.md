# Secured Lab

A local ethical-hacking practice platform with a modern Flask GUI, authenticated dashboard, browser terminal, internal training target, and GitHub repository search.

## What is included

- Flask web application
- Login/registration with password hashing
- CSRF protection and security headers
- User-scoped notes and API
- Browser terminal using xterm.js + node-pty
- Disposable Debian terminal containers
- Internal Docker lab network
- Safe internal training target
- GitHub public repository search
- 8 guided security exercises

The browser terminal architecture uses xterm.js for terminal rendering and node-pty for the PTY. node-pty recommends putting server-launched PTYs inside containers when the server is exposed. Docker provides namespaces/cgroups and capability controls for container isolation.

## Important safety requirement

The terminal service mounts the Docker socket because it must create disposable terminal containers. Docker documents that access to the Docker daemon is powerful and should be restricted. Run this project only on a dedicated lab machine or VM and never expose port 7681 or the Docker socket to the Internet.

The compose lab network is internal and the training target has no published host port.

## Run the web application

Python:

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Create local secrets:

    cp .env.example .env

Set SECRET_KEY and TERMINAL_SECRET to long random values.

Start Flask:

    python app.py

Open:

    http://127.0.0.1:5000

## Run the terminal/lab infrastructure

Requirements:

- Docker Engine + Docker Compose
- Linux is recommended for the full Docker lab

Build and start:

    docker compose --env-file .env up --build

The terminal service listens only on:

    127.0.0.1:7681

Then sign in to the web application and open Terminal.

## GitHub search

The GitHub page uses the GitHub REST API. GitHub search is rate-limited; there is no technically unlimited public GitHub search. The application supports normal pagination and optionally accepts a server-side GITHUB_TOKEN for authenticated API requests. Never put a GitHub token in browser JavaScript or commit it to the repository.

## Android / Termux

The Flask portion runs in Termux. The full browser-terminal Docker architecture requires a Docker-capable Linux host. Standard Android/Termux is not a replacement for a Docker Engine host, so use the web application in Termux and run the full lab infrastructure on a Linux VM/PC.

## Lab scope

The internal target is deliberately safe and does not execute arbitrary SQL, HTML, commands, or uploads. It provides training endpoints and clues so you can practice reconnaissance, HTTP analysis, headers, API inspection and secure coding without publishing a remotely exploitable target.

Only test systems you own or have explicit permission to assess.
