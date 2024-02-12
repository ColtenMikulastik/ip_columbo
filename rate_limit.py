
import time


class rate_limit:
    """ class that makes sure api requests are within limits """
    api_name = "def_name"
    rate_per_min = 4
    api_context = 0
    first_request_time = 0.0

    def __init__(self, api_name, rate_per_min):
        """ requires api name for object """
        self.api_name = api_name
        self.rate_per_min = rate_per_min

    def update_context(self):
        """ updates context of api based on a number of variables """

        # check and set bool based on time difference
        if (time.time() - self.first_request_time) < 60:
            is_less_than_min = True
        else:
            is_less_than_min = False
            self.api_context = 0

        # if it's the first time the api has been called set time
        if self.api_context == 0:
            self.first_request_time = time.time()
        # check to see if limit is broken and it's been more than a min
        elif self.api_context >= self.rate_per_min and is_less_than_min:
            return False

        # iterate teh context
        self.api_context = self.api_context + 1
