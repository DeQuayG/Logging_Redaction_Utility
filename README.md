# Logging_Redaction_Utility  
A set of subclasses that override `logging.Formatter` and `logging.Filter`, combined with a decorator factory for easy integration with named loggers.  

In this example, the wrapped function makes a simple request to retrieve and update a list of known malicious IPs from an OSINT source.  

The logger decorator factory wraps the function, produces a named logger with its own filter, and redacts any sensitive data emitted during the function call.  

----------

## Nitty-Gritty  

- **Redaction Formatter Class** -> recursively removes sensitive keys (`user_id`, `token`, `password`, `ip`) from structured logs using DFS.  
- **String Redaction Filter** -> uses regex-based redaction for unstructured log strings, so nothing slips through the cracks.  
- **Logger Decorator Factory** -> enables modular integration of logging, named loggers, and per-function log levels for any Python function you choose to wrap.  

----------

### Additional Jazzy Functionality  

- Per-function log levels (`DEBUG`, `INFO`, etc.)  
- A toggleable debug trace flag to inspect pre-redacted logs  
- Optional JSON output for structured logging pipelines  

----------

## My Inspiration for this Project
Security and observability, or rather security and engineering in general sometimes clash. Sometimes you need detailed logs, but you can’t risk leaking any secrets.  

This utility allows for safe logging by default while staying flexible enough for debugging and pipeline integration.
