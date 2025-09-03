import functools
import logging
from logging import StreamHandler
from logging.handlers import RotatingFileHandler
import requests 
from dotenv import load_dotenv 
import os
import csv
import json
import re


load_dotenv()


URL = "https://api/abuseipdb.com/api/v2/blacklist"
SENSITIVE_KEYS = {"api_key", "user_id", "token", "password", "ip"}

def log_decorator_factory(func_log_level, logger_name):
  def decorator(func):
    final_logger_name = func.__name__ if logger_name == "func_name" else logger_name

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      logger = logging.getLogger(final_logger_name)
      logger.setLevel(getattr(logging, func_log_level.upper(), logging.info))
      handler = RotatingFileHandler("test.log", maxBytes=10_000, backupCount=10)

      if not logger.handlers: # pretty standard way of preventing logging duplication
        logger.addHandler(handler)
        formatter = RedactionFormatter() 
        handler.setFormatter(formatter)
        string_filter = StringRedactionFilter()
        handler.addFilter(string_filter)

      logger.info(f"Log level set to: {func_log_level} for: {final_logger_name}")
      result = func(*args, **kwargs)

      logger.info({
        "event": "function_call",
        "function": func.__name__,
        "args": args,
        "kwargs": kwargs
    })

      logger.info(f"Function {func.__name__} finished")
      return result
    return wrapper
  return decorator


# This is a subclass of the logging.Formatter python built in class 
# It extends the functionality of the formatter, which is
# Then injected into the logger decorator factory
class RedactionFormatter(logging.Formatter):
  def __init__(self, sensitive_keys=None, debug_trace=False, as_json=False): # These are just flags, corresponding to logic below
    super().__init__(fmt="%(asctime)s | %(name)s | %(funcName)s | %(message)s")
    self.debug_trace = debug_trace 
    self.as_json = as_json
    self.sensitive_keys = {str(key).lower() for key in (sensitive_keys if sensitive_keys else SENSITIVE_KEYS)}
  
  def recursive_redact(self, data):
    if isinstance(data, dict):
        return {
            key: ("REDACTED" 
                  if str(key).lower() in self.sensitive_keys
                  else self.recursive_redact(value))
                  for key, value in data.items()
        }
    elif isinstance(data, list):
        return [self.recursive_redact(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(self.recursive_redact(item) for item in data)
    else:
        return data
    
  def format(self, record):
      msg = record.msg

      try:
          if isinstance(record.msg, dict): 
            redacted_msg = self.recursive_redact(record.msg)
            record.msg = json.dumps(redacted_msg) if self.as_json else redacted_msg
      except Exception:
          logging.debug("Redaction Failed!")
          redacted_msg = str(redacted_msg) 

      else:
         redacted_msg = str(redacted_msg)

      if self.debug_trace:
          print("DEBUG TRACE:", msg)
      
      
      record.msg = redacted_msg
      return super().format(record)


class StringRedactionFilter(logging.Filter):
    def __init__(self, sensitive_keys=None, redaction_text="REDACTED"):
        super().__init__()
        self.sensitive_keys = sensitive_keys if sensitive_keys else SENSITIVE_KEYS
        self.redaction_text = redaction_text
        self.patterns = self.regex_patterns()

    def regex_patterns(self):
        return [
            re.compile(rf"{key}\s*=\s*['\"]?[\w\-\.@:]{{4,}}['\"]?", re.IGNORECASE)
            for key in self.sensitive_keys
        ]
    

    def filter(self, record):
      if isinstance(record.msg, str):
          for pattern in self.patterns:
              record.msg = pattern.sub(
                  lambda match: re.sub(r'([:=]).*$', rf"\1 {self.redaction_text}", match.group()),
                  record.msg
              )
      return True




@log_decorator_factory(func_log_level="DEBUG", logger_name="func_name")
def grab_osint_list(url, API_KEY):
  url=URL
  API_KEY=API_KEY
  query_string = {
    'limit': '10000'
  }

  headers = {
    'Accept':'text/plain',
    'Key':API_KEY
  }

  logging.info(f"Attempting to fetch blacklist from {url}")

  try:
    response = requests.request(method='GET', url=URL, headers=headers, params=query_string)
    response.raise_for_status() # auto raises status for 4XX and 5XX calls 

    with open("known_bad_ips.csv", "w", newline='') as file:
      writer = csv.writer(file)
      writer.writerow(["ipv4_address"])  # must be a list
      lines = response.text.strip().splitlines()
      rows = [[line.strip()] for line in lines if line.strip()]
      writer.writerows(rows)

      logging.info("Successfully saved IPs")

  except Exception as e:
    logging.warning(f"An error occurred: {e}")
    logging.warning(f"Error Response: {response.text}")
    logging.warning(f"Error: {response.content}")



if __name__ == '__main__': 
  API_KEY = os.getenv("API_KEY")

  if not API_KEY:
    logging.error("Error: API_KEY Environment Variable not set. Exiting")
    exit(1)

  ip_address = grab_osint_list(url=URL, API_KEY=API_KEY)

  if not ip_address: 
    logging.warning("NO IP's Grabbed!. Exiting.")
    exit(1)