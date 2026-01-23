# Contributing to ansible-role-rhel-rke2-stig

Thank you for your interest in contributing to this STIG compliance role!

## Code of Conduct

Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Include RHEL version, Ansible version, and relevant STIG IDs
- Provide steps to reproduce the issue

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/RHEL-09-XXXXXX
   ```
3. **Follow the code style** documented in CLAUDE.md:
   - Comments wrap at 80 characters
   - Use FQCN for all modules (`ansible.builtin.*`)
   - Include STIG comment blocks for all tasks
4. **Test your changes**:
   ```bash
   yamllint .
   ansible-lint
   molecule test
   ```
5. **Commit** with a descriptive message:
   ```bash
   git commit -m "Add RHEL-09-XXXXXX: Brief description"
   ```
6. **Push** and open a Pull Request

### Task Structure

All tasks must follow this format:

```yaml
###########################################################
# STIG ID: RHEL-09-XXXXXX    Group ID: V-XXXXXX
# Rule Title: Full title from STIG (wrap at 80 chars with
#   continuation on next line)
# Severity: CAT I | CAT II | CAT III
###########################################################
- name: RHEL-09-XXXXXX | Brief description
  ansible.builtin.module_name:
    param: value
  tags:
    - RHEL-09-XXXXXX
    - CAT II
```

### Adding New STIG Controls

1. Reference the authoritative XCCDF file for accurate metadata
2. Add variables to `vars/main.yml` if using templates
3. Update the README.md STIG coverage tables
4. Include verification in `molecule/default/verify.yml`

## Questions?

Open an issue with the `question` label.
