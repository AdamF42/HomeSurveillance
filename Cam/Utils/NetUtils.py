import socket
import time


class NetworkError(RuntimeError):
    pass


def retryer(max_retries=30, timeout=5):
    def wraps(func):
        exceptions = (
            socket.herror,
            socket.gaierror,
            socket.timeout,
            ConnectionError
        )

        def inner(*args, **kwargs):
            for i in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                except exceptions:
                    time.sleep(timeout)
                    continue
                else:
                    return result
            else:
                raise NetworkError

        return inner

    return wraps
