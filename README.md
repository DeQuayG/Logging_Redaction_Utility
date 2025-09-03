# Logging_Redaction_Utility
A couple of subclasses that override logging.Formatter and logging.Filter, with a decorator factory for ease of integration for named loggers.

In this case as and example, the wrapped function is a simple request to retrieve and update a list of known malicious IP's from an OSINT source. 

The logger decorator factory will wrap the function, produce a named logger with it's own filter, and then redact anything sensitive that's emitted by the function call.

