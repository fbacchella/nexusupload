import logging

logger = logging.getLogger('nexuslib.exceptions')

class NexusException(Exception):
    def __init__(self, status, body, content_type, http_message, url=None):
        self.status_code = status
        self.http_message = http_message
        if url is not None:
            self.url = url

    def __str__(self):
        return str(self.http_message)

