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

### RKE2 Operational Requirements

This role also deploys RKE2-specific configurations that are not direct STIG
requirements but are necessary for Kubernetes operation:

| Configuration | File Deployed | Purpose |
|---------------|---------------|---------|
| Kernel Modules | `/etc/modules-load.d/rke2-modules.conf` | Load networking modules for CNI |
| Sysctl Tuning | `/etc/sysctl.d/98-rke2.conf` | Kernel parameters for K8s networking |
| NetworkManager | `/etc/NetworkManager/conf.d/rke2-canal.conf` | Ignore CNI interfaces |
| RKE2 Audit Rules | `/etc/audit/rules.d/10-rke2-server.rules` | Audit K8s components |
| fapolicyd Rules | `/etc/fapolicyd/rules.d/60-rke2.rules` | Whitelist storage paths |
| Firewalld | Service disabled and masked | RKE2 uses iptables directly |

## STIG Exemptions Required

The following STIG controls require documented exemptions when deploying RKE2
Kubernetes nodes. These exemptions must be coordinated with your Information
System Security Officer (ISSO) and documented in the System Security Plan (SSP).

### Exemption Summary

| STIG ID | Group ID | Severity | Rule Title | Justification |
|---------|----------|----------|------------|---------------|
| [RHEL-09-253075](#rhel-09-253075-ipv4-packet-forwarding) | V-257970 | CAT II | IPv4 packet forwarding must be disabled | Required for Kubernetes pod networking |
| [RHEL-09-251015](#rhel-09-251015--rhel-09-251020-firewalld-service) | V-257936 | CAT II | firewalld service must be active | RKE2 iptables conflicts with firewalld |
| [RHEL-09-251020](#rhel-09-251015--rhel-09-251020-firewalld-service) | V-257937 | CAT II | Firewall deny-all policy required | Consequent to RHEL-09-251015 |

---

### RHEL-09-253075: IPv4 Packet Forwarding

| Field | Value |
|-------|-------|
| **STIG ID** | RHEL-09-253075 |
| **Group ID** | V-257970 |
| **Severity** | CAT II (Medium) |
| **Rule Title** | RHEL 9 must not enable IPv4 packet forwarding unless the system is a router |
| **Status** | EXEMPTION REQUIRED |

#### STIG Requirement

The STIG requires `net.ipv4.ip_forward = 0` and `net.ipv4.conf.all.forwarding = 0`
to prevent the system from forwarding IPv4 packets unless it is designated as a
router.

#### This Role's Setting

This role sets `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/98-rke2.conf`.

#### Justification

Kubernetes nodes **require** IPv4 packet forwarding to be enabled for pod-to-pod
networking to function. The node acts as a router for container network traffic
in the CNI (Container Network Interface) overlay network. Without IP forwarding:

- Pods cannot communicate across nodes
- Services cannot route traffic to backend pods
- The Kubernetes cluster is non-functional

This is a fundamental architectural requirement of Kubernetes networking, not a
misconfiguration.

#### Impact Assessment

| Aspect | Assessment |
|--------|------------|
| **Risk Level** | Low |
| **Attack Vector** | Local network only; requires existing network access |
| **Compensating Controls** | See below |

#### Compensating Controls

The following controls mitigate the risk of enabling IP forwarding:

1. **Network Segmentation**: RKE2 nodes are deployed on isolated network segments
   with firewall rules restricting traffic to authorized sources only
2. **CNI Network Policies**: Kubernetes NetworkPolicy resources restrict pod-to-pod
   communication to authorized flows
3. **Source Routing Disabled**: The following STIG-compliant settings prevent
   source-routed packet exploitation:
   - `net.ipv4.conf.all.accept_source_route = 0`
   - `net.ipv4.conf.default.accept_source_route = 0`
4. **ICMP Redirects Disabled**: Redirect acceptance is disabled per STIG requirements
5. **RKE2 iptables Rules**: RKE2 implements iptables-based network filtering that
   restricts traffic to required Kubernetes ports (see RHEL-09-251015 exemption)

#### Remediation Path

| Condition | Action |
|-----------|--------|
| **If node is decommissioned** | Remove from Kubernetes cluster and disable IP forwarding |
| **If STIG is updated** | Review for Kubernetes-specific guidance that may supersede this exemption |
| **Alternative** | None available - IP forwarding is architecturally required for Kubernetes |

#### STIG Reference

Per the STIG check content: *"If the IPv4 forwarding value is not '0' **and is
not documented with the information system security officer (ISSO) as an
operational requirement**, this is a finding."*

This exemption documents the operational requirement as permitted by the STIG.

#### Documentation Template for ISSO

```
STIG Exemption Request

System: [System Name]
STIG ID: RHEL-09-253075
Control: IPv4 Packet Forwarding

Operational Requirement: The system is a Kubernetes (RKE2) node that requires
IPv4 packet forwarding for container networking. Kubernetes CNI networking
fundamentally depends on the node forwarding packets between the pod network
overlay and external networks.

Compensating Controls:
- Network segmentation isolates RKE2 nodes
- Kubernetes NetworkPolicy restricts pod communication
- Source routing and ICMP redirects remain disabled per STIG
- RKE2 iptables rules provide network filtering (see RHEL-09-251015 exemption)

Risk Acceptance: [ISSO Signature and Date]
```

### RHEL-09-251015 / RHEL-09-251020: Firewalld Service

| Field | Value |
|-------|-------|
| **STIG ID** | RHEL-09-251015 |
| **Group ID** | V-257936 |
| **Severity** | CAT II (Medium) |
| **Rule Title** | The firewalld service on RHEL 9 must be active |
| **Status** | EXEMPTION REQUIRED |

| Field | Value |
|-------|-------|
| **STIG ID** | RHEL-09-251020 |
| **Group ID** | V-257937 |
| **Severity** | CAT II (Medium) |
| **Rule Title** | The RHEL 9 firewall must employ a deny-all, allow-by-exception policy |
| **Status** | EXEMPTION REQUIRED (consequent to RHEL-09-251015) |

#### STIG Requirement

RHEL-09-251015 requires the firewalld service to be active and running.
RHEL-09-251020 requires firewalld to be configured with a deny-all, allow-by-
exception policy using firewall zones.

#### This Role's Setting

This role stops, disables, and masks the firewalld service.

#### Justification

RKE2 Kubernetes uses **iptables directly** to manage pod networking, service
load balancing, and network policy enforcement. Running firewalld concurrently
with RKE2's iptables management causes:

- **Rule conflicts**: firewalld and RKE2 both manipulate iptables, leading to
  unpredictable rule ordering and dropped packets
- **Silent failures**: Cluster networking fails intermittently in ways that are
  difficult to diagnose (pods cannot communicate, services become unreachable)
- **Race conditions**: Both systems attempt to manage the same iptables chains,
  causing rules to be overwritten or deleted unexpectedly

Despite extensive testing with firewalld configurations (including custom zones,
direct rules, and rich rules), stable coexistence has not been achievable. This
is a known limitation documented by Rancher and other Kubernetes distributions.

**RKE2's iptables rules ARE a firewall.** They implement:
- Default deny for pod ingress (unless allowed by NetworkPolicy)
- SNAT/DNAT for service load balancing
- Port filtering based on defined Kubernetes services
- Network isolation between namespaces (when NetworkPolicy is configured)

#### Impact Assessment

| Aspect | Assessment |
|--------|------------|
| **Risk Level** | Low |
| **Attack Vector** | Network-based; mitigated by external controls |
| **Compensating Controls** | See below |

#### Compensating Controls

1. **RKE2 iptables Firewall**: RKE2 implements comprehensive iptables rules that
   filter traffic to only allowed Kubernetes services and pods
2. **Kubernetes NetworkPolicy**: CNI-level network policies restrict pod-to-pod
   communication based on labels, namespaces, and ports
3. **Network Segmentation**: RKE2 nodes are deployed on isolated network segments
   with upstream firewall/ACLs restricting access to management and service ports
4. **Ingress Controllers**: External traffic enters only through designated ingress
   points with TLS termination and request filtering
5. **Service Mesh** (if deployed): mTLS between services provides encryption and
   authentication at the application layer
6. **API Server Authentication**: Kubernetes API requires valid certificates and
   RBAC authorization for all requests

#### Ports Exposed by RKE2 (Filtered by iptables)

| Port | Protocol | Purpose | Exposure |
|------|----------|---------|----------|
| 6443 | TCP | Kubernetes API | Control plane |
| 9345 | TCP | RKE2 supervisor | Control plane |
| 10250 | TCP | Kubelet API | All nodes |
| 2379-2380 | TCP | etcd | Control plane |
| 8472 | UDP | VXLAN (Canal) | All nodes |
| 30000-32767 | TCP/UDP | NodePort services | As configured |

#### Remediation Path

| Condition | Action |
|-----------|--------|
| **If node is decommissioned** | Re-enable firewalld after removing from cluster |
| **If RKE2 adds firewalld support** | Review Rancher documentation for integration guidance |
| **Alternative** | External network firewall/ACLs provide perimeter filtering |

#### Documentation Template for ISSO

```
STIG Exemption Request

System: [System Name]
STIG IDs: RHEL-09-251015, RHEL-09-251020
Controls: Firewalld Service Active, Deny-All Firewall Policy

Operational Requirement: The system is a Kubernetes (RKE2) node. RKE2 manages
network filtering directly via iptables for pod networking, service routing,
and network policy enforcement. Running firewalld concurrently causes iptables
rule conflicts resulting in cluster networking failures.

Compensating Controls:
- RKE2 iptables rules provide network filtering for all K8s traffic
- Kubernetes NetworkPolicy enforces pod-to-pod communication restrictions
- Network segmentation with upstream firewalls restricts node access
- Only required Kubernetes ports are exposed (6443, 9345, 10250, etc.)

Technical Justification: RKE2 and firewalld both manage iptables chains. Their
concurrent operation causes rule conflicts, race conditions, and silent
networking failures. This incompatibility is documented by Rancher (RKE2
vendor) and is a known limitation of running firewalld with Kubernetes.

Risk Acceptance: [ISSO Signature and Date]
```

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
| `/etc/audit/rules.d/10-rke2-server.rules` | RKE2-specific audit rules |
| `/etc/modprobe.d/blacklist.conf` | Kernel module blacklist |
| `/etc/modules-load.d/rke2-modules.conf` | Kernel modules for K8s networking |
| `/etc/sysctl.d/98-rke2.conf` | Kernel tuning for Kubernetes |
| `/etc/NetworkManager/conf.d/rke2-canal.conf` | CNI interface ignore list |
| `/etc/fapolicyd/rules.d/60-rke2.rules` | Application whitelist for storage |

## Development Setup

### Pre-commit Hooks

This repository uses pre-commit hooks to catch issues before pushing:

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install

# (Optional) Run against all files
pre-commit run --all-files
```

Once installed, yamllint and ansible-lint run automatically on every commit.

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
