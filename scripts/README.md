# Automation Scripts

The Ralph automation suite is implemented in Rust. Use the `ralph` command instead of shell scripts:

```bash
# Context building
ralph context -o context.txt
ralph context -m docs -o docs-context.txt

# Archive management
ralph archive --stale-days 90 --dry-run
ralph archive --stale-days 90

# Project analysis
ralph analyze

# Main loop
ralph loop plan --max-iterations 5
ralph loop build --max-iterations 50

# Analytics
ralph analytics --last 10
```

For legacy compatibility, you can also use:
```bash
ralph bootstrap  # Set up project structure
```
