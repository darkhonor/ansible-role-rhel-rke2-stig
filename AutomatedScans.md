# Automated Scanning Analysis

This document details discrepancies between automated security scanning tools and
the authoritative DISA STIG releases. Understanding these gaps is critical for
accurate compliance assessments.

## OpenSCAP Data Stream Analysis

- **Analysis Date:** January 2026
- **Source Package:** `scap-security-guide-0.1.79-1.el9.noarch`
- **OpenSCAP Data Stream:** `ssg-rhel9-ds.xml` (based on V2R5, dated 2025-12-02)
- **Authoritative STIG:** RHEL 9 STIG V2R7 (released January 2026)

> **Note:** This analysis is based on the SCAP content from the package version
> listed above. When the `scap-security-guide` package is updated, this analysis
> must be re-evaluated against the new data stream content.

### Summary

| Metric | Count |
|--------|-------|
| V2R7 STIG Rules | 446 |
| OpenSCAP Rules | 447 |
| Scanner Gaps (missing from OpenSCAP) | 8 |
| False Positives (deprecated rules in OpenSCAP) | 4 |
| Phantom IDs (in OpenSCAP, never existed in DISA STIG) | 5 |

**Key Finding:** The OpenSCAP data stream is **2 releases behind** the current
V2R7 STIG. Most critically, it's missing the **CAT I** rule RHEL-09-672020 for
crypto policy override prevention.

---

## Scanner Gaps - Manual Checks Required

These V2R7 STIG rules are **NOT checked by OpenSCAP** and require manual
verification. Copy-paste bash scripts are provided for each.

### RHEL-09-672020 | CAT I | Crypto Policy Override Prevention

**Title:** RHEL 9 cryptographic policy must not be overridden.

**Group ID:** V-258236

**Why This Matters:** This is a **CAT I (High)** finding. Overridden crypto
policies can allow weak cryptographic algorithms, undermining FIPS compliance.

```bash
#!/bin/bash
# RHEL-09-672020 - Verify crypto policy is not overridden
# Severity: CAT I (High)

echo "=== RHEL-09-672020: Crypto Policy Override Check ==="
echo ""

# Check if configured policy matches generated policy
echo "Checking crypto policy consistency..."
policy_check=$(sudo update-crypto-policies --check 2>&1)
echo "$policy_check"
echo ""

if echo "$policy_check" | grep -q "does NOT match"; then
    echo "[FAIL] Crypto policy has been overridden!"
    exit 1
fi

# Verify backend symlinks point to correct policy location
echo "Checking crypto backend symlinks..."
current_policy=$(update-crypto-policies --show)
expected_path="/usr/share/crypto-policies/${current_policy}"

fail_count=0
for backend in /etc/crypto-policies/back-ends/*.config; do
    if [ -L "$backend" ]; then
        target=$(readlink -f "$backend")
        # nss.config is not a symlink by design
        if [[ "$backend" != *"nss.config"* ]] && [[ ! "$target" =~ ^/usr/share/crypto-policies/ ]]; then
            echo "[FAIL] $backend -> $target (should point to $expected_path/)"
            ((fail_count++))
        fi
    elif [[ "$backend" != *"nss.config"* ]]; then
        echo "[WARN] $backend is not a symlink (may be overridden)"
        ((fail_count++))
    fi
done

if [ $fail_count -eq 0 ]; then
    echo "[PASS] All crypto backends properly configured"
    exit 0
else
    echo ""
    echo "[FAIL] $fail_count backend(s) may be overridden"
    exit 1
fi
```

---

### RHEL-09-654097 | CAT II | Audit Cron Scripts

**Title:** RHEL 9 must audit any script or executable called by cron as root or
by any privileged user.

**Group ID:** V-279936

**Note:** This rule was added in V2R7 and does not exist in earlier STIG
releases.

```bash
#!/bin/bash
# RHEL-09-654097 - Verify cron directories are audited
# Severity: CAT II (Medium)
# Note: New rule in V2R7

echo "=== RHEL-09-654097: Cron Audit Rules Check ==="
echo ""

fail_count=0

# Check /etc/cron.d audit rule
echo "Checking audit rule for /etc/cron.d..."
crond_rule=$(sudo auditctl -l 2>/dev/null | grep "/etc/cron.d")
if [ -n "$crond_rule" ]; then
    echo "[PASS] $crond_rule"
else
    echo "[FAIL] No audit rule found for /etc/cron.d"
    ((fail_count++))
fi

# Check /var/spool/cron audit rule
echo "Checking audit rule for /var/spool/cron..."
spool_rule=$(sudo auditctl -l 2>/dev/null | grep "/var/spool/cron")
if [ -n "$spool_rule" ]; then
    echo "[PASS] $spool_rule"
else
    echo "[FAIL] No audit rule found for /var/spool/cron"
    ((fail_count++))
fi

echo ""
if [ $fail_count -eq 0 ]; then
    echo "[PASS] All cron audit rules configured"
    exit 0
else
    echo "[FAIL] Missing $fail_count cron audit rule(s)"
    echo ""
    echo "Fix: Add the following to /etc/audit/rules.d/cronjobs.rules:"
    echo "  -w /etc/cron.d -p wa -k cronjobs"
    echo "  -w /var/spool/cron -p wa -k cronjobs"
    exit 1
fi
```

---

### RHEL-09-654270 | CAT II | Protect Logon UIDs

**Title:** RHEL 9 audit system must protect logon UIDs from unauthorized change.

**Group ID:** V-258228

```bash
#!/bin/bash
# RHEL-09-654270 - Verify loginuid immutability
# Severity: CAT II (Medium)

echo "=== RHEL-09-654270: Logon UID Protection Check ==="
echo ""

echo "Checking for --loginuid-immutable in audit rules..."
immutable_check=$(sudo grep -i "loginuid-immutable" /etc/audit/audit.rules 2>/dev/null)

if [ -n "$immutable_check" ]; then
    echo "[PASS] Found: $immutable_check"
    exit 0
else
    echo "[FAIL] --loginuid-immutable not found in /etc/audit/audit.rules"
    echo ""
    echo "Fix: Add the following to the end of /etc/audit/rules.d/99-finalize.rules:"
    echo "  --loginuid-immutable"
    echo ""
    echo "Then regenerate rules with: sudo augenrules --load"
    exit 1
fi
```

---

### RHEL-09-214030 | CAT II | Cryptographic Hash Verification

**Title:** RHEL 9 must be configured so that the cryptographic hashes of system
files match vendor values.

**Group ID:** V-257823

```bash
#!/bin/bash
# RHEL-09-214030 - Verify system file hashes match vendor values
# Severity: CAT II (Medium)
# Note: This check can take several minutes to complete

echo "=== RHEL-09-214030: System File Hash Verification ==="
echo ""
echo "This check may take several minutes..."
echo ""

# Find files with hash mismatches (excluding config files)
mismatches=$(sudo rpm -Va --noconfig 2>/dev/null | awk '$1 ~ /..5/ && $2 != "c"')

if [ -z "$mismatches" ]; then
    echo "[PASS] All system file hashes match vendor values"
    exit 0
else
    echo "[FAIL] The following files have hash mismatches:"
    echo ""
    echo "$mismatches"
    echo ""
    echo "Investigate each file. Legitimate changes may occur from patches."
    echo "Unauthorized modifications indicate potential compromise."
    exit 1
fi
```

---

### RHEL-09-215030 | CAT II | ypserv Package Not Installed

**Title:** RHEL 9 must not have the ypserv package installed.

**Group ID:** V-257829

```bash
#!/bin/bash
# RHEL-09-215030 - Verify ypserv is not installed
# Severity: CAT II (Medium)

echo "=== RHEL-09-215030: ypserv Package Check ==="
echo ""

if dnf list --installed ypserv &>/dev/null; then
    echo "[FAIL] ypserv package is installed"
    echo ""
    echo "Fix: sudo dnf remove ypserv"
    exit 1
else
    echo "[PASS] ypserv package is not installed"
    exit 0
fi
```

---

### RHEL-09-215035 | CAT II | EPEL Repository Disabled

**Title:** RHEL 9 must not install packages from the Extra Packages for
Enterprise Linux (EPEL) repository.

**Group ID:** V-257830

```bash
#!/bin/bash
# RHEL-09-215035 - Verify EPEL repository is not enabled
# Severity: CAT II (Medium)

echo "=== RHEL-09-215035: EPEL Repository Check ==="
echo ""

epel_repos=$(dnf repolist 2>/dev/null | grep -i epel)

if [ -n "$epel_repos" ]; then
    echo "[FAIL] EPEL repository is enabled:"
    echo "$epel_repos"
    echo ""
    echo "Fix: sudo dnf config-manager --set-disabled epel"
    echo "Or remove the EPEL repo file from /etc/yum.repos.d/"
    exit 1
else
    echo "[PASS] No EPEL repositories enabled"
    exit 0
fi
```

> **Exception Consideration:** This requirement was added in V2R6 (previously
> this STIG ID covered rsh-server). EPEL packages are prohibited because they
> are not from Red Hat, not covered under support agreements, and not vetted
> through official supply chains. However, many environments legitimately
> require EPEL packages for monitoring agents, operational tools, or other
> software not available in base RHEL repositories.
>
> If EPEL is operationally required, document an exception with:
> - Specific EPEL packages required and business justification
> - Compensating controls (package vetting, vulnerability scanning, etc.)
> - AO approval for the exception
>
> See the project's `CLAUDE.md` for exception documentation format.

---

### RHEL-09-215065 | CAT II | quagga Package Not Installed

**Title:** RHEL 9 must not have the quagga package installed.

**Group ID:** V-257836

```bash
#!/bin/bash
# RHEL-09-215065 - Verify quagga is not installed
# Severity: CAT II (Medium)

echo "=== RHEL-09-215065: quagga Package Check ==="
echo ""

if dnf list --installed quagga &>/dev/null; then
    echo "[FAIL] quagga package is installed"
    echo ""
    echo "If this is an operational requirement, document with ISSO."
    echo "Otherwise fix with: sudo dnf remove quagga"
    exit 1
else
    echo "[PASS] quagga package is not installed"
    exit 0
fi
```

---

### RHEL-09-211035 | CAT III | Hardware RNG Entropy Service

**Title:** RHEL 9 must enable the hardware random number generator entropy
gatherer service.

**Group ID:** V-257782

**Note:** This requirement is **Not Applicable** for systems running with kernel
FIPS mode enabled (RHEL-09-671010).

```bash
#!/bin/bash
# RHEL-09-211035 - Verify rngd service is active
# Severity: CAT III (Low)
# Note: N/A for systems with FIPS mode enabled

echo "=== RHEL-09-211035: Hardware RNG Service Check ==="
echo ""

# Check if FIPS mode is enabled (makes this N/A)
if [ -f /proc/sys/crypto/fips_enabled ] && [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]; then
    echo "[N/A] FIPS mode is enabled - this check is Not Applicable"
    echo "Per RHEL-09-671010, FIPS mode provides sufficient entropy"
    exit 0
fi

# Check rngd service status
if systemctl is-active rngd &>/dev/null; then
    echo "[PASS] rngd service is active"
    exit 0
else
    echo "[FAIL] rngd service is not active"
    echo ""
    echo "Fix:"
    echo "  sudo dnf install rng-tools"
    echo "  sudo systemctl enable --now rngd"
    exit 1
fi
```

---

## Combined Scanner Gap Check Script

Run all scanner gap checks at once:

```bash
#!/bin/bash
# run-stig-gap-checks.sh
# Runs all V2R7 STIG checks that OpenSCAP misses
# Usage: sudo ./run-stig-gap-checks.sh

echo "=============================================="
echo "RHEL 9 STIG V2R7 - OpenSCAP Gap Checks"
echo "=============================================="
echo ""

total=0
passed=0
failed=0
na=0

run_check() {
    local stig_id="$1"
    local severity="$2"
    local description="$3"
    shift 3

    ((total++))
    echo "[$stig_id] ($severity) $description"
    if "$@"; then
        ((passed++))
        echo "  Result: PASS"
    else
        result=$?
        if [ $result -eq 2 ]; then
            ((na++))
            echo "  Result: N/A"
        else
            ((failed++))
            echo "  Result: FAIL"
        fi
    fi
    echo ""
}

# CAT I Checks
check_672020() {
    # Part 1: Verify configured policy matches generated policy
    policy_check=$(update-crypto-policies --check 2>&1)
    if echo "$policy_check" | grep -q "does NOT match"; then
        return 1
    fi

    # Part 2: Verify backend symlinks point to correct policy location
    current_policy=$(update-crypto-policies --show)
    for backend in /etc/crypto-policies/back-ends/*.config; do
        [ -e "$backend" ] || continue
        # nss.config is not a symlink by design
        [[ "$backend" == *"nss.config"* ]] && continue
        if [ -L "$backend" ]; then
            target=$(readlink -f "$backend")
            if [[ ! "$target" =~ ^/usr/share/crypto-policies/ ]]; then
                return 1
            fi
        else
            # Non-symlink backend (except nss.config) indicates override
            return 1
        fi
    done
    return 0
}

# CAT II Checks
check_654097() {
    local fail=0
    auditctl -l 2>/dev/null | grep -q "/etc/cron.d" || ((fail++))
    auditctl -l 2>/dev/null | grep -q "/var/spool/cron" || ((fail++))
    [ $fail -eq 0 ]
}

check_654270() {
    grep -qi "loginuid-immutable" /etc/audit/audit.rules 2>/dev/null
}

check_214030() {
    [ -z "$(rpm -Va --noconfig 2>/dev/null | awk '$1 ~ /..5/ && $2 != \"c\"')" ]
}

check_215030() {
    ! dnf list --installed ypserv &>/dev/null
}

check_215035() {
    ! dnf repolist 2>/dev/null | grep -qi epel
}

check_215065() {
    ! dnf list --installed quagga &>/dev/null
}

# CAT III Checks
check_211035() {
    if [ -f /proc/sys/crypto/fips_enabled ] && [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]; then
        return 2  # N/A
    fi
    systemctl is-active rngd &>/dev/null
}

# Run all checks
run_check "RHEL-09-672020" "CAT I" "Crypto policy not overridden" check_672020
run_check "RHEL-09-654097" "CAT II" "Cron directories audited" check_654097
run_check "RHEL-09-654270" "CAT II" "Logon UIDs protected" check_654270
run_check "RHEL-09-214030" "CAT II" "File hashes match vendor" check_214030
run_check "RHEL-09-215030" "CAT II" "ypserv not installed" check_215030
run_check "RHEL-09-215035" "CAT II" "EPEL not enabled" check_215035
run_check "RHEL-09-215065" "CAT II" "quagga not installed" check_215065
run_check "RHEL-09-211035" "CAT III" "rngd service active" check_211035

# Summary
echo "=============================================="
echo "Summary: $passed passed, $failed failed, $na N/A (of $total checks)"
echo "=============================================="

if [ $failed -gt 0 ]; then
    exit 1
fi
exit 0
```

---

## False Positives - Kubernetes/Domain Environments

These findings are **expected behavior** in RKE2/K3S Kubernetes environments and
systems joined to Active Directory or FreeIPA. Document as false positives.

### RHEL-09-232250 / RHEL-09-232255 | Orphaned Files in Container Paths

**STIG IDs:** RHEL-09-232250, RHEL-09-232255
**Group IDs:** V-257930, V-257931
**Severity:** CAT II

**Scanner Behavior:** Automated scanners (Nessus, OpenSCAP, SCAP Compliance
Checker) will flag files under `/var/lib/rancher` as having no valid owner
or group owner.

**Why This is a False Positive:**

1. **Container User Namespaces**: Files under `/var/lib/rancher` belong to
   container processes using mapped UIDs (e.g., 100000-165535) that
   intentionally don't exist in `/etc/passwd`. This is a **security feature**
   called user namespace isolation.

2. **Container Image UIDs**: Container images define their own users (nginx,
   postgres, etc.) with UIDs that differ from host users by design.

3. **Domain User Homes**: If the system is joined to AD/IPA, files under
   `/home/<DOMAIN>/` are owned by directory service UIDs resolved via SSSD
   at runtime, not local passwd entries.

**Affected Paths:**
- `/var/lib/rancher/rke2` - RKE2 Kubernetes data
- `/var/lib/rancher/k3s` - K3S Kubernetes data
- `/var/lib/rancher/longhorn` - Longhorn CSI volumes
- `/var/lib/rancher/local-path-provisioner` - Local-path PVs
- `/home/<DOMAIN>/` - Domain user home directories (if SSSD enabled)

**Verification Script:**

```bash
#!/bin/bash
# Verify orphaned files are only in expected container/domain paths
# Any orphans OUTSIDE these paths are real findings

echo "=== RHEL-09-232250/232255: Orphaned File Analysis ==="
echo ""

# Define expected exclusion paths
RANCHER_PATH="/var/lib/rancher"
DOMAIN_PATH="/home/contoso.com"  # Adjust for your domain

echo "Checking for orphaned files OUTSIDE expected paths..."
echo "(Files in $RANCHER_PATH and $DOMAIN_PATH are expected)"
echo ""

# Find orphans excluding known container/domain paths
orphans=$(find / -xdev \
    -path "$RANCHER_PATH" -prune -o \
    -path "$DOMAIN_PATH" -prune -o \
    \( -nouser -o -nogroup \) -print 2>/dev/null)

if [ -z "$orphans" ]; then
    echo "[PASS] No unexpected orphaned files found"
    echo ""
    echo "Note: Files in $RANCHER_PATH are container UIDs (expected)"
    echo "Note: Files in $DOMAIN_PATH are domain UIDs (expected)"
    exit 0
else
    echo "[FAIL] Orphaned files found outside container/domain paths:"
    echo "$orphans"
    exit 1
fi
```

**Handling:** When reviewing scan results:
1. Filter findings for paths under `/var/lib/rancher`
2. Filter findings for domain home directory paths
3. Only investigate orphaned files outside these paths
4. Document the exemption per README.md STIG Exemptions section

---

## False Positives - Deprecated Rules

These rules were **deprecated in V2R7** but OpenSCAP will still check for them.
Any findings for these rules should be marked as **false positives**.

| STIG ID | Status | Notes |
|---------|--------|-------|
| RHEL-09-411115 | Deprecated in V2R7 | Merged with other controls |
| RHEL-09-412075 | Deprecated in V2R7 | Merged with other controls |
| RHEL-09-654096 | Deprecated in V2R7 | Superseded by RHEL-09-654097 |
| RHEL-09-654260 | Deprecated in V2R7 | Merged with other audit controls |

**Handling:** When reviewing OpenSCAP scan results, filter out findings for these
STIG IDs. Document that these are false positives due to scanner version lag.

---

## Phantom IDs - Invalid STIG References

These STIG IDs exist in the OpenSCAP data stream but have **never existed** in
any DISA RHEL 9 STIG release (V2R5, V2R6, or V2R7).

| OpenSCAP ID | Notes |
|-------------|-------|
| RHEL-09-255055 | Not in any DISA STIG |
| RHEL-09-255060 | Not in any DISA STIG |
| RHEL-09-653115 | Not in any DISA STIG |
| RHEL-09-672025 | Not in any DISA STIG |
| RHEL-09-672030 | Not in any DISA STIG |

**Root Cause:** These appear to be SCAP Content (SSG) internal rules that were
incorrectly mapped to non-existent STIG IDs. They may represent draft rules that
were never finalized in official DISA releases.

**Handling:** Findings for these IDs cannot be mapped to official STIG
requirements. Document as scanner artifacts and exclude from formal compliance
reporting against DISA STIG baselines.

---

## Recommendations

1. **Check for SCAP Content Updates:** Periodically check if the
   `scap-security-guide` package has been updated:

   ```bash
   # Check installed version
   rpm -q scap-security-guide

   # Check for available updates
   dnf check-update scap-security-guide
   ```

   When the package is updated, re-run this analysis to identify changes in
   scanner coverage.

2. **Update OpenSCAP Content:** When Red Hat releases updated SCAP content
   aligned with V2R7, update the data stream files and re-evaluate this
   document.

3. **Supplement with Manual Checks:** Use the bash scripts in this document to
   check rules not covered by OpenSCAP, especially the CAT I rule.

4. **Document False Positives:** Create a scan exception list for deprecated
   rules to streamline compliance reporting.

5. **Monitor STIG Releases:** DISA typically releases STIG updates quarterly.
   Re-analyze scanner gaps after each new release.

---

## References

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [OpenSCAP Project](https://www.open-scap.org/)
- [SCAP Security Guide (SSG)](https://github.com/ComplianceAsCode/content)
- [Red Hat SCAP Content](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/scanning-the-system-for-configuration-compliance-and-vulnerabilities_security-hardening)
