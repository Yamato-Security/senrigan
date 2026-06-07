# TDD Guide — Test-Driven Development

## Language Policy

All test names, test comments, docstrings, and documentation in this project MUST be written in English.

## Philosophy

This project follows the TDD methodology, based on Kent Beck's _Test-Driven Development: By Example_. The core belief is:

> **"Clean code that works"** — first make it work, then make it clean.

TDD is not just a testing technique — it is a **design methodology** that drives the architecture of your code through tests.

## The Red-Green-Refactor Cycle

```
        ┌──────────┐
        │  RED     │  Write a failing test
        │  (fail)  │
        └────┬─────┘
             │
             ▼
        ┌──────────┐
        │  GREEN   │  Write minimum code to pass
        │  (pass)  │
        └────┬─────┘
             │
             ▼
        ┌──────────┐
        │ REFACTOR │  Clean up, remove duplication
        │  (pass)  │
        └────┬─────┘
             │
             └───────▶ Repeat
```

### Red Phase

- Write **one** test for **one** specific behavior.
- Run the test. It **must fail**.
- If it passes, either the test is wrong or the behavior is already implemented.
- The failure message should clearly describe what is missing.

### Green Phase

- Write the **minimum** code to make the failing test pass.
- It is okay to hardcode values, write ugly code, or take shortcuts.
- The only goal is to see the test turn green.
- Do **not** add functionality beyond what the test requires.

### Refactor Phase

- Now that tests are green, improve the code.
- Remove duplication (DRY).
- Improve naming, extract functions, simplify logic.
- Run tests after **every** change — they must stay green.
- If a refactoring breaks a test, undo and try a smaller step.

## Key Techniques

### 1. Test List

Before writing any code, create a **test list** — a checklist of all behaviors you want to verify.

```markdown
## Test List: CloudTrail JSON Parser

- [ ] Parse a single CloudTrail event from JSON
- [ ] Parse a file with multiple Records
- [ ] Handle missing optional fields (errorCode, etc.)
- [ ] Return error on malformed JSON
- [ ] Handle empty Records array
```

Start with the simplest item. Cross off items as you implement them. Add new items as you discover them.

### 2. Baby Steps

Make the **smallest possible change** at each step. If you find yourself writing more than 5-10 lines of production code at once, you're taking too large a step.

Bad (too large):
```
Write entire parser module → Write all tests → Debug
```

Good (baby steps):
```
Test: parse one field → Implement one field
Test: parse two fields → Extend struct
Test: handle missing field → Add Option<T>
Test: parse full event → Connect all fields
```

### 3. Triangulation

When you're unsure about the correct generalization, **add more specific test cases** to "triangulate" toward the general solution.

Example in Rust:
```rust
// First test — might be tempted to hardcode
#[test]
fn test_parse_event_name() {
    let json = r#"{"eventName": "DescribeInstances", ...}"#;
    let event = parse_event(json).unwrap();
    assert_eq!(event.event_name, "DescribeInstances");
}

// Second test — forces generalization
#[test]
fn test_parse_different_event_name() {
    let json = r#"{"eventName": "CreateUser", ...}"#;
    let event = parse_event(json).unwrap();
    assert_eq!(event.event_name, "CreateUser");
}
```

### 4. Fake It Till You Make It

In the Green phase, it's perfectly acceptable to fake the implementation:

```rust
// Green phase — fake it
fn parse_event(_json: &str) -> Result<CloudTrailEvent> {
    Ok(CloudTrailEvent {
        event_name: "DescribeInstances".to_string(),
        // ...hardcoded values...
    })
}
```

Then triangulate with more tests to force the real implementation.

### 5. Obvious Implementation

When the implementation is **obvious** and you're confident, skip faking and write the real code directly. But if the test fails unexpectedly, fall back to smaller steps.

## TDD Walkthrough: ingester Module

### Feature: Parse a CloudTrail JSON file

#### Step 1: Test List

```markdown
- [ ] Parse a minimal single-event JSON
- [ ] Parse Records array with multiple events
- [ ] Handle missing optional fields
- [ ] Reject malformed JSON
- [ ] Handle empty Records array
```

#### Step 2: Red — First failing test

```rust
// src/parser.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_cloudtrail_event() {
        let json = r#"{
            "Records": [{
                "eventTime": "2024-01-15T10:30:00Z",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-east-1"
            }]
        }"#;

        let log = parse_cloudtrail_log(json).unwrap();
        assert_eq!(log.records.len(), 1);
        assert_eq!(log.records[0].event_name, "DescribeInstances");
    }
}
```

Run: `cargo test test_parse_single_cloudtrail_event` → **RED** (compile error: `parse_cloudtrail_log` doesn't exist)

#### Step 3: Green — Minimum implementation

```rust
// src/parser.rs
use serde::Deserialize;
use anyhow::Result;

#[derive(Debug, Deserialize)]
pub struct CloudTrailEvent {
    #[serde(rename = "eventName")]
    pub event_name: String,
    #[serde(rename = "eventTime")]
    pub event_time: String,
    #[serde(rename = "eventSource")]
    pub event_source: String,
    #[serde(rename = "awsRegion")]
    pub aws_region: String,
}

#[derive(Debug, Deserialize)]
pub struct CloudTrailLog {
    #[serde(rename = "Records")]
    pub records: Vec<CloudTrailEvent>,
}

pub fn parse_cloudtrail_log(json: &str) -> Result<CloudTrailLog> {
    let log: CloudTrailLog = serde_json::from_str(json)?;
    Ok(log)
}
```

Run: `cargo test test_parse_single_cloudtrail_event` → **GREEN** ✓

#### Step 4: Refactor

Nothing to refactor yet — the code is already clean. Move to the next test.

#### Step 5: Next test — Multiple records

```rust
#[test]
fn test_parse_multiple_records() {
    let json = r#"{
        "Records": [
            {"eventTime": "2024-01-15T10:30:00Z", "eventName": "DescribeInstances",
             "eventSource": "ec2.amazonaws.com", "awsRegion": "us-east-1"},
            {"eventTime": "2024-01-15T10:31:00Z", "eventName": "CreateUser",
             "eventSource": "iam.amazonaws.com", "awsRegion": "us-east-1"}
        ]
    }"#;

    let log = parse_cloudtrail_log(json).unwrap();
    assert_eq!(log.records.len(), 2);
    assert_eq!(log.records[1].event_name, "CreateUser");
}
```

This already passes (serde handles arrays) → consider if the test is redundant, or keep it as documentation.

#### Step 6: Next test — Optional fields

```rust
#[test]
fn test_parse_handles_missing_optional_fields() {
    let json = r#"{
        "Records": [{
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1"
        }]
    }"#;
    // No errorCode, sourceIPAddress, etc.

    let log = parse_cloudtrail_log(json).unwrap();
    assert!(log.records[0].error_code.is_none());
}
```

**RED** → `error_code` field doesn't exist on the struct yet.

**GREEN** → Add `pub error_code: Option<String>` with `#[serde(rename = "errorCode")]`.

Continue this cycle for all items in the test list.

## TDD Walkthrough: agent Module

### Feature: SQL Query Validation

#### Step 1: Test List

```markdown
- [ ] Accept a valid SELECT query
- [ ] Reject an INSERT statement
- [ ] Reject a DROP TABLE statement
- [ ] Reject a DELETE statement
- [ ] Case-insensitive rejection
- [ ] Accept queries with subqueries containing write keywords in strings
```

#### Step 2: Red — First failing test

```python
# tests/test_query.py

def test_validate_accepts_select_query():
    from query import validate_sql_blocklist
    sql = "SELECT event_name FROM cloudtrail_events LIMIT 10"
    validate_sql_blocklist(sql)  # should not raise
```

Run: `pytest tests/test_query.py::test_validate_accepts_select_query` → **RED** (ImportError)

#### Step 3: Green

```python
# query.py

def validate_sql_blocklist(sql: str) -> None:
    pass  # fake implementation — never raises
```

**GREEN** ✓ (fake implementation — always passes)

#### Step 4: Triangulate — Add a failing case

```python
def test_validate_rejects_insert():
    from query import QueryValidationError, validate_sql_blocklist
    sql = "INSERT INTO cloudtrail_events VALUES (...)"
    with pytest.raises(QueryValidationError):
        validate_sql_blocklist(sql)
```

**RED** → Now we need a real implementation.

```python
# query.py
import re

FORBIDDEN_KEYWORDS = re.compile(
    r'\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b',
    re.IGNORECASE,
)


class QueryValidationError(Exception):
    pass


def validate_sql_blocklist(sql: str) -> None:
    """Raise QueryValidationError if the SQL contains forbidden write keywords."""
    if FORBIDDEN_KEYWORDS.search(sql):
        raise QueryValidationError(f"SQL contains forbidden keyword: {sql[:80]}")
```

**GREEN** ✓

Continue the cycle for remaining test list items.

## Anti-Patterns to Avoid

| Anti-Pattern                          | Why It's Harmful                                                  |
| ------------------------------------- | ----------------------------------------------------------------- |
| Writing tests after implementation    | Tests become confirmation bias, not design drivers                |
| Writing multiple tests at once        | Lose the feedback loop; harder to isolate failures                |
| Making the test pass "properly" first | Skip the fake/obvious step; leads to over-engineering             |
| Refactoring while tests are red       | No safety net; changes may introduce bugs                         |
| Skipping the test list                | Leads to ad-hoc, incomplete coverage                              |
| Large steps                           | When something breaks, hard to find the cause                     |

## When to Break the Rules

TDD is a discipline, not a religion. It's acceptable to skip strict TDD for:

- **Boilerplate code** (Dockerfile, docker-compose.yml, config files)
- **UI layout** (Streamlit widget placement — but test the logic behind it)
- **Third-party integration wiring** (but mock and test the interface layer)

Always test **business logic and data transformations** using TDD.

