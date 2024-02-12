
import time


class rate_limit:
    """ class that makes sure api requests are within limits """

    # time_metric is the time in seconds between context reset
    # default four requests per min
    time_metric = 60
    rate_per_time_metric = 4
    api_context = 0
    first_request_time = 0.0

    def __init__(self, rate_per_time_metric=4, time_metric=60):
        """ requires api name for object """
        self.rate_per_time_metric = rate_per_time_metric
        self.time_metric = time_metric

    def update_context(self):
        """ updates context of api based on a number of variables """

        # check and set bool based on time difference
        if (time.time() - self.first_request_time) < self.time_metric:
            is_less_than_time_metric = True
        else:
            is_less_than_time_metric = False
            self.api_context = 0

        # if it's the first time the api has been called set time
        if self.api_context == 0:
            self.first_request_time = time.time()
        # check to see if limit is broken and it's been more than a min
        elif self.api_context >= self.rate_per_time_metric and is_less_than_time_metric:
            return False

        # iterate teh context
        self.api_context = self.api_context + 1
