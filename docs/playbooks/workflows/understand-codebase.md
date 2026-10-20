# Workflow: Understand a Codebase

You've cloned an unfamiliar repository. Here's how Claude uses narsil-xref to help you understand it.

## The Scenario

You're new to a project and need to understand:
- What the project does
- How it's organized
- Where key functionality lives
- How components connect

## Example Conversation

### Step 1: Get the big picture

**You:** "What is this project and how is it structured?"

**Claude calls:**
```
get_project_structure(repo: "myproject")
```

**Result:** Claude sees the directory tree:
```
myproject/
├── src/
│   ├── api/
│   │   ├── routes.py
│   │   ├── auth.py
│   │   └── handlers.py
│   ├── models/
│   │   ├── user.py
│   │   └── order.py
│   ├── services/
│   │   ├── payment.py
│   │   └── email.py
│   └── main.py
├── tests/
├── docs/
└── requirements.txt
```

**Claude responds:** "This is a Python web API with a typical layered architecture..."

---

### Step 2: Find entry points

**You:** "Where does the application start? What are the main entry points?"

**Claude calls:**
```
find_symbols(repo: "myproject", symbol_type: "function", pattern: "main*")
search_code(query: "if __name__", repo: "myproject")
find_symbols(repo: "myproject", symbol_type: "function", pattern: "*route*")
```

**Result:** Claude finds:
- `main.py:15` - `def main()`
- `api/routes.py` - Route definitions with `@app.route` decorators

**Claude responds:** "The application starts in `main.py` which initializes the Flask app. API routes are defined in `api/routes.py`..."

---

### Step 3: Understand a specific feature

**You:** "How does authentication work?"

**Claude calls:**
```
search_code(query: "authentication login token", repo: "myproject")
find_symbols(repo: "myproject", pattern: "*auth*")
get_file(repo: "myproject", path: "src/api/auth.py")
get_callers(repo: "myproject", function: "authenticate")
```

**Result:** Claude reads the auth module and traces how it's used.

**Claude responds:** "Authentication uses JWT tokens. The flow is:
1. User calls `/login` with credentials
2. `authenticate()` in `auth.py:42` validates and returns a token
3. Protected routes use the `@require_auth` decorator
4. Token is validated on each request by `verify_token()` at line 78..."

---

### Step 4: Map dependencies

**You:** "What external libraries does this use?"

**Claude calls:**
```
get_dependencies(repo: "myproject", path: "requirements.txt")
```

**Result:** Claude sees all dependencies.

**Claude responds:** "The project uses Flask, SQLAlchemy, PyJWT, and Redis..."

---

### Step 5: Trace data flow

**You:** "How does a request flow from the API to the database?"

**Claude calls:**
```
get_callers(repo: "myproject", function: "create_order", transitive: true)
get_callees(repo: "myproject", function: "create_order", transitive: true)
find_call_path(repo: "myproject", from: "handle_order", to: "db_session.commit")
```

**Result:** Claude traces the entire call chain.

**Claude responds:** "When a POST hits `/orders`:
1. `routes.py:handle_order()` validates input
2. Calls `services/order.py:create_order()`
3. Which calls `models/order.py:Order.create()`
4. Finally commits via SQLAlchemy's `db_session.commit()`..."

## Tools Used in This Workflow

| Tool | Purpose |
|------|---------|
| `get_project_structure` | See directory layout and file organization |
| `find_symbols` | Find classes, functions, methods by name pattern |
| `search_code` | Full-text search across the codebase |
| `get_file` | Read specific source files |
| `get_dependencies` | Analyze imports and requirements |
| `get_callers` | Find what calls a function |
| `get_callees` | Find what a function calls |
| `find_call_path` | Trace path between two functions |

## Tips

1. **Start broad, then narrow:** Begin with structure, then drill into specific features

2. **Let Claude explore:** Don't micromanage - ask questions and let Claude choose which tools to use

3. **Use follow-up questions:** "What else calls that function?" or "Show me the actual code"

4. **Enable all features:** Use `--git --call-graph` flags for the richest understanding

## Sample Prompts

```
"Give me an overview of this codebase"
"What are the main components and how do they interact?"
"Find all the API endpoints"
"How is data validated before reaching the database?"
"What's the relationship between User and Order models?"
"Show me the dependency graph for the auth module"
"Where is configuration loaded from?"
"What design patterns does this project use?"
```

## Related Workflows

- [Fix a Bug](fix-a-bug.md) - Now that you understand the code, debug an issue
- [Code Review](code-review.md) - Review changes effectively
