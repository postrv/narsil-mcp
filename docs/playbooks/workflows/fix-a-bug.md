# Workflow: Fix a Bug

You have a bug report. Here's how Claude uses narsil-xref to help you diagnose and fix it.

## The Scenario

**Bug report:** "Users report getting 'Invalid token' errors randomly, even with valid sessions"

You need to:
- Find the relevant code
- Understand the data flow
- Identify the root cause
- Verify the fix won't break other things

## Example Conversation

### Step 1: Locate the error

**You:** "I'm getting 'Invalid token' errors. Find where this error message comes from."

**Claude calls:**
```
search_code(query: "Invalid token", repo: "myproject")
```

**Result:**
```
src/api/auth.py:87: raise AuthError("Invalid token")
src/api/auth.py:94: raise AuthError("Invalid token: expired")
src/api/auth.py:101: raise AuthError("Invalid token: malformed")
```

**Claude responds:** "The 'Invalid token' error is raised in three places in `auth.py`. Let me get more context..."

**Claude calls:**
```
get_excerpt(repo: "myproject", path: "src/api/auth.py", lines: [87, 94, 101], expand_to_scope: true)
```

---

### Step 2: Understand the validation logic

**You:** "Show me the token validation logic"

**Claude calls:**
```
get_symbol_definition(repo: "myproject", symbol: "verify_token")
get_control_flow(repo: "myproject", path: "src/api/auth.py", function: "verify_token")
```

**Result:** Claude sees the function and its control flow graph (branches, conditions, etc.)

**Claude responds:** "The `verify_token` function at line 75:
1. Checks if token is present
2. Decodes the JWT
3. Validates expiration
4. Checks the signature
5. Verifies the user still exists

The control flow shows there are 4 paths that can raise 'Invalid token'..."

---

### Step 3: Trace the data flow

**You:** "Where does the token come from? Trace how it flows into this function."

**Claude calls:**
```
get_callers(repo: "myproject", function: "verify_token")
get_data_flow(repo: "myproject", path: "src/api/auth.py", function: "verify_token")
```

**Result:** Claude traces from HTTP header → middleware → verify_token

**Claude responds:** "Token flow:
1. Extracted from `Authorization` header in `middleware.py:23`
2. Passed to `verify_token()` at `middleware.py:31`

I see a potential issue - the token is extracted with `split(' ')[1]` which could fail if the header format is wrong..."

---

### Step 4: Check recent changes

**You:** "When did this start happening? Check the git history for this file."

**Claude calls:**
```
get_symbol_history(repo: "myproject", path: "src/api/auth.py", symbol: "verify_token")
get_blame(repo: "myproject", path: "src/api/auth.py", start_line: 75, end_line: 110)
```

**Result:**
```
commit a3f2b1c (3 days ago): "Refactor token validation"
  - Changed: line 89 - added timezone handling
  - Author: dev@example.com
```

**Claude responds:** "Found it! Three days ago, commit `a3f2b1c` changed the token expiration check. The new code uses `datetime.utcnow()` but the token was created with `datetime.now()`. There's a timezone mismatch causing valid tokens to appear expired."

---

### Step 5: Verify fix won't break things

**You:** "Before I fix this, what else uses this function? I don't want to break anything."

**Claude calls:**
```
get_callers(repo: "myproject", function: "verify_token", transitive: true)
find_symbol_usages(repo: "myproject", symbol: "verify_token")
```

**Result:**
```
Callers:
  - middleware.py:require_auth() → verify_token()
  - tests/test_auth.py:test_valid_token() → verify_token()
  - api/websocket.py:authenticate_ws() → verify_token()
```

**Claude responds:** "3 places call `verify_token`:
1. The auth middleware (for all protected routes)
2. Test file (has tests for this!)
3. WebSocket authentication

Your fix should maintain the same function signature. The existing tests should catch regressions."

---

### Step 6: Analyze complexity

**You:** "Is this function overly complex? Should I refactor it?"

**Claude calls:**
```
get_complexity(repo: "myproject", function: "verify_token")
```

**Result:**
```
Cyclomatic complexity: 8
Cognitive complexity: 12
```

**Claude responds:** "The function has cyclomatic complexity of 8 (moderate) and cognitive complexity of 12 (starting to get complex). After your fix, consider refactoring the validation steps into smaller functions."

## Tools Used in This Workflow

| Tool | Purpose |
|------|---------|
| `search_code` | Find error messages and relevant code |
| `get_excerpt` | Get code with surrounding context |
| `get_symbol_definition` | Get full function/class source |
| `get_control_flow` | See branches, loops, and conditions |
| `get_data_flow` | Track variable definitions and uses |
| `get_callers` | Find what calls a function |
| `get_symbol_history` | See git history for a specific function |
| `get_blame` | See who changed each line and when |
| `get_complexity` | Measure cyclomatic/cognitive complexity |

## Debugging Patterns

### "Error shows up randomly"
```
get_data_flow → find unhandled edge cases
get_control_flow → identify all code paths
```

### "Worked before, broke recently"
```
get_symbol_history → find when function changed
get_commit_diff → see exactly what changed
```

### "Works for some users, not others"
```
get_data_flow → trace where user-specific data enters
find_call_path → trace difference in execution paths
```

### "Performance degraded"
```
get_callers + transitive → find all paths to slow code
get_complexity → identify overly complex functions
get_hotspots → find files with high churn and complexity
```

## Sample Prompts

```
"Find where this error message comes from"
"Trace how this variable gets its value"
"What changed in this function recently?"
"Show me all the ways this function can fail"
"What else uses this code? Will my fix break anything?"
"Is there a race condition here?"
"Who should I ask about this code?"
```

## Related Workflows

- [Understand a Codebase](understand-codebase.md) - Get context first
- [Code Review](code-review.md) - Review your fix before merging
