# scrt4

The crypto core and the per-OS clients. This is the code the repository exists
for; everything above this directory is documentation and recovery tooling.

```
daemon/src/     the Rust daemon — vault, auth ceremony, secret injection
daemon/bin/     the bash client
windows/        the PowerShell client and its launcher
install/        the native installer
scripts/        build tooling
```

- **What it is and how it works:** [../README.md](../README.md)
- **Building and installing from source:** [../BUILD.md](../BUILD.md)
- **Recovering a vault without scrt4:** [../disaster-recovery/](../disaster-recovery)
- **Threat model:** [SECURITY.md](./SECURITY.md)
- **Design rationale:** [daemon/DESIGN.md](./daemon/DESIGN.md)
