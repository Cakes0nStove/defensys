from datetime import datetime
# this nicely formats the time
def iso_now():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")