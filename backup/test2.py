from concurrent.futures import ThreadPoolExecutor
import time

def wait_on_future():
    time.sleep(1)
    print("1 sec")
    
    # This will never complete because there is only one worker thread and
    # it is executing this function.
    executor.submit(wait_on_future)

executor = ThreadPoolExecutor(max_workers=1)
executor.submit(wait_on_future)

while True:
    pass