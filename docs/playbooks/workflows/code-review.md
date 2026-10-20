# Workflow: Code Review

Use narsil-xref to review code changes effectively, understanding context and implications.

## The Scenario

A pull request is ready for review. You need to:
- Understand what changed
- Check for bugs or issues
- Verify the changes won't break existing functionality
- Assess code quality and complexity

## Example Conversation

### Step 1: See what changed

**You:** "Show me what files were modified recently"

**Claude calls:**
```
get_modified_files(repo: "myproject")
get_recent_changes(repo: "myproject", days: 7)
```

**Result:**
```
Modified files:
  M src/api/orders.py
  M src/services/payment.py
  A src/services/refund.py
  M tests/test_orders.py

Recent commits:
  abc123 - Add refund functionality (2 days ago)
  def456 - Update payment service (3 days ago)
```

**Claude responds:** "The recent changes add refund functionality. 3 modified files and 1 new file. Let me review each..."

---

### Step 2: Understand the new code

**You:** "Show me the new refund service"

**Claude calls:**
```
get_file(repo: "myproject", path: "src/services/refund.py")
find_symbols(repo: "myproject", file_pattern: "refund.py")
get_complexity(repo: "myproject", function: "process_refund")
```

**Result:**
```
Symbols in refund.py:
  - class RefundService
  - method process_refund (complexity: 6)
  - method validate_refund (complexity: 3)
  - method notify_customer (complexity: 2)

Cyclomatic complexity of process_refund: 6 (acceptable)
```

**Claude responds:** "The new RefundService has clean separation of concerns. `process_refund` has moderate complexity (6) - acceptable for a payment flow. Let me check the logic..."

---

### Step 3: Check how it integrates

**You:** "How does this integrate with the existing payment service?"

**Claude calls:**
```
get_dependencies(repo: "myproject", path: "src/services/refund.py")
get_callers(repo: "myproject", function: "process_refund")
find_call_path(repo: "myproject", from: "handle_refund_request", to: "process_refund")
```

**Result:**
```
refund.py imports:
  - from .payment import PaymentService
  - from ..models.order import Order

Callers of process_refund:
  - api/orders.py:handle_refund_request() at line 156

Call path:
  handle_refund_request() → validate_order() → process_refund()
```

**Claude responds:** "The refund service correctly uses the existing PaymentService. The call path is clean: API handler validates, then delegates to the refund service."

---

### Step 5: Check the diff

**You:** "What exactly changed in the payment service?"

**Claude calls:**
```
get_commit_diff(repo: "myproject", commit: "def456", path: "src/services/payment.py")
get_blame(repo: "myproject", path: "src/services/payment.py", start_line: 80, end_line: 120)
```

**Result:**
```diff
+ def process_refund(self, order_id: str, amount: Decimal) -> RefundResult:
+     """Process a refund for an order."""
+     order = self.get_order(order_id)
+     if amount > order.total:
+         raise ValueError("Refund exceeds order total")
+     return self.gateway.refund(order.payment_id, amount)
```

**Claude responds:** "The payment service added a `process_refund` method. It correctly validates the refund amount against the order total. The implementation delegates to the payment gateway."

---

### Step 6: Check test coverage

**You:** "Are the new features tested?"

**Claude calls:**
```
search_code(query: "def test_refund", repo: "myproject")
get_file(repo: "myproject", path: "tests/test_orders.py", start_line: 100, end_line: 150)
```

**Result:**
```
Found tests:
  - test_refund_success (tests/test_orders.py:105)
  - test_refund_exceeds_total (tests/test_orders.py:118)
  - test_refund_invalid_order (tests/test_orders.py:130)
```

**Claude responds:** "Good test coverage. Tests cover:
- Happy path (successful refund)
- Error case (refund exceeds total)
- Error case (invalid order)

Consider adding tests for partial refunds and concurrent refund attempts."

---

### Step 7: Identify impact

**You:** "What other code might be affected by these changes?"

**Claude calls:**
```
find_symbol_usages(repo: "myproject", symbol: "PaymentService")
get_callers(repo: "myproject", function: "get_order", transitive: true)
```

**Result:**
```
PaymentService used in:
  - api/orders.py (import + usage)
  - api/subscriptions.py (import + usage)
  - services/refund.py (import + usage)
  - tests/test_payment.py (mocking)

get_order callers:
  - process_order (orders.py)
  - process_refund (payment.py)
  - cancel_subscription (subscriptions.py)
```

**Claude responds:** "The changes could affect subscriptions if they share order handling. Verify `cancel_subscription` still works correctly. The PaymentService mock in tests should be updated."

---

## Tools Used in This Workflow

| Tool | Purpose |
|------|---------|
| `get_modified_files` | See what files changed |
| `get_recent_changes` | See recent commit history |
| `get_commit_diff` | See exactly what changed in a commit |
| `get_blame` | See who changed each line |
| `find_symbols` | Understand new code structure |
| `get_complexity` | Assess code complexity |
| `get_callers` / `get_callees` | Understand integration points |

## Review Checklist

Claude can help verify:

- [ ] **Functionality:** Does the code do what it claims?
- [ ] **Integration:** How does it connect to existing code?
- [ ] **Security:** Any vulnerabilities introduced?
- [ ] **Tests:** Are changes tested?
- [ ] **Impact:** What else might break?
- [ ] **Quality:** Dead code, type errors, complexity?

## Sample Prompts

```
"Review the recent changes to this project"
"What does this new function do?"
"Is this change safe? What might it break?"
"Check the new code for security issues"
"Who wrote this code? When was it changed?"
"Are the new features properly tested?"
"What's the complexity of this function?"
"Find any dead code or unused variables"
```

## Related Workflows

- [Understand a Codebase](understand-codebase.md) - Get context before reviewing
- [Fix a Bug](fix-a-bug.md) - Debug issues found in review
