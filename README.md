# Ansible Role: RHEL RKE2 STIG Compliance

[![CI](https://github.com/darkhonor/ansible-role-rhel-rke2-stig/actions/workflows/ci.yml/badge.svg)](https://github.com/darkhonor/ansible-role-rhel-rke2-stig/actions/workflows/ci.yml)
[![Ansible Galaxy](https://img.shields.io/badge/galaxy-darkhonor.rhel__rke2__stig-blue.svg)](https://galaxy.ansible.com/darkhonor/rhel_rke2_stig)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Supplementary Ansible role for enforcing DISA STIG compliance on RHEL 9/10
systems running RKE2 or K3S Kubernetes distributions.

## Overview

This role is designed to run **after** the operating system is installed with a
STIG profile applied (e.g., via RHEL's OSCAP Anaconda addon). It fills in gaps
and adds kernel/system-level configurations required for Kubernetes nodes in
DoD environments.

**This role does NOT implement the full RHEL STIG.** It assumes the base STIG
profile was applied at install time and handles:

- Missing or incomplete STIG settings post-installation
- Audit rules for system call monitoring and privileged commands
- Kernel module blacklisting for attack surface reduction
- System tuning common to RKE2/K3S Kubernetes nodes

## Requirements

- **Ansible:** 2.10 or higher
- **Python:** 3.9 or higher on control node
- **Target OS:** RHEL 9 or RHEL 10 (Enterprise Linux family)
- **Privileges:** Root access required on target hosts
- **Pre-requisite:** STIG profile applied during OS installation

### Ansible Collections

This role requires the following collections (installed automatically if using
`ansible-galaxy`):

```yaml
collections:
  - ansible.posix
  - community.general
```

## Role Variables

### Static Variables (vars/main.yml)

These variables define STIG-required configurations and should not typically be
modified:

| Variable | Description |
|----------|-------------|
| `rhel9_rke2_stig_audit_rules` | List of 50 audit rule definitions with STIG metadata |
| `rhel9_rke2_stig_blacklist_modules` | List of 8 kernel modules to blacklist |

### Default Variables (defaults/main.yml)

*Note: Default variables for enabling/disabling specific controls will be added
in future releases.*

## STIG Coverage

This role currently addresses **59 STIG findings**:

### Password Policy (1 finding)

| STIG ID | Severity | Description |
|---------|----------|-------------|
| RHEL-09-611075 | CAT II | Minimum password lifetime (24 hours) |

### Audit Rules (50 findings)

| STIG ID Range | Severity | Description |
|---------------|----------|-------------|
| RHEL-09-654010 - 654080 | CAT II | System call auditing (execve, chmod, chown, etc.) |
| RHEL-09-654085 - 654175 | CAT II | Privileged command auditing (passwd, sudo, su, etc.) |
| RHEL-09-654180 - 654210 | CAT II | Mount/system control auditing |
| RHEL-09-654215 - 654255 | CAT II | Identity file change auditing |

### Kernel Module Blacklist (8 findings)

| STIG ID | Severity | Module | Description |
|---------|----------|--------|-------------|
| RHEL-09-213045 | CAT II | atm | Asynchronous Transfer Mode |
| RHEL-09-213050 | CAT II | can | Controller Area Network |
| RHEL-09-213055 | CAT II | firewire-core | FireWire |
| RHEL-09-213060 | CAT II | sctp | Stream Control Transmission Protocol |
| RHEL-09-213065 | CAT II | tipc | Transparent Inter Process Communication |
| RHEL-09-231195 | CAT III | cramfs | Compressed ROM filesystem |
| RHEL-09-291010 | CAT II | usb-storage | USB mass storage |
| RHEL-09-291035 | CAT II | bluetooth | Bluetooth |

## Dependencies

None. This role is designed to be standalone.

## Example Playbook

### Basic Usage

```yaml
---
- name: Apply STIG compliance to RKE2 nodes
  hosts: rke2_nodes
  become: true
  roles:
    - role: darkhonor.rhel_rke2_stig
```

### With Tags

```yaml
---
- name: Apply specific STIG controls
  hosts: rke2_nodes
  become: true
  roles:
    - role: darkhonor.rhel_rke2_stig
      tags:
        - audit
        - kernel
```

### Running Specific Tags

```bash
# Apply only audit rules
ansible-playbook site.yml --tags audit

# Apply only kernel module blacklist
ansible-playbook site.yml --tags kernel

# Apply specific STIG finding
ansible-playbook site.yml --tags RHEL-09-611075
```

## Files Deployed

| File | Description |
|------|-------------|
| `/etc/audit/rules.d/20-stig.rules` | STIG-compliant audit rules |
| `/etc/modprobe.d/blacklist.conf` | Kernel module blacklist |

## Testing

This role is tested using Molecule with Podman:

```bash
# Install test dependencies
pip install molecule molecule-plugins[podman] ansible-lint yamllint

# Run full test suite
molecule test

# Run converge only (apply role)
molecule converge

# Run verification tests
molecule verify

# Clean up test environment
molecule destroy
```

### CI/CD

Automated testing runs on every push and pull request:

- **Linting:** yamllint, ansible-lint
- **Syntax:** ansible-playbook --syntax-check
- **Integration:** Molecule with UBI9 container
- **Security:** Trivy vulnerability scanning

## Compliance References

- [RHEL 9 STIG V2R6](https://public.cyber.mil/stigs/) - Primary OS hardening
- [RKE2 STIG V2R4](https://public.cyber.mil/stigs/) - Kubernetes controls
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Control framework
- [FIPS 140-2/140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program) - Cryptographic requirements

## RKE2/K3S Considerations

When deploying this role to Kubernetes nodes, be aware of:

- **Firewall:** RKE2 requires specific ports (6443, 9345, 10250, 2379-2380)
- **SELinux:** Must remain in enforcing mode; RKE2 policies may need tuning
- **Audit volume:** Kubernetes syscalls generate high audit log volume
- **etcd:** Requires separate TLS and backup configuration

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-stig-control`)
3. Commit your changes (`git commit -am 'Add RHEL-09-XXXXXX control'`)
4. Push to the branch (`git push origin feature/new-stig-control`)
5. Open a Pull Request

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Author Information

**Alex Ackerman**

- GitHub: [@darkhonor](https://github.com/darkhonor)
- Galaxy: [darkhonor](https://galaxy.ansible.com/darkhonor)

---

*This role is provided as-is for educational and operational purposes. Always
test in a non-production environment before deploying to production systems.
Ensure compliance with your organization's security policies and change
management procedures.*
