from threading import Thread


class ThreadWithCallback(Thread):
    def __init__(self, *args, **kwargs):
        self.target = kwargs.pop("target")
        self.callback = kwargs.pop("callback")
        self.callback_kwargs = kwargs.pop("callback_kwargs")
        super().__init__(target=self.target_with_callback, *args, **kwargs)

    def target_with_callback(self, *args, **kwargs):
        self.target(*args, **kwargs)
        if self.callback_kwargs:
            self.callback(**self.callback_kwargs)
        else:
            self.callback()
