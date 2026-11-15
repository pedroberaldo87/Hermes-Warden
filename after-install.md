## Hermes Warden installed

Next steps:

1. Open Hermes Desktop (or the Webapp) and pick **Warden** in the sidebar.
2. The tab checks for the Bitwarden CLI (`bw`). If it is missing, press **Install Bitwarden CLI**
   (Homebrew, npm or the official Bitwarden build, checksum-verified).
3. Choose your server, log in and unlock. Passwords go only into masked dialogs.

From the agent: ask it to "check Bitwarden" (it calls `warden_status`).
macOS and Linux only. Docs: README.md in this folder.
