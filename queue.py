from threading import Semaphore, Lock


lock = Lock()


def synchronized(f):
    def g(*args):
        lock.acquire()
        res = f(*args)
        lock.release()
        return res
    return g


class Queue:

    def __init__(self):
        self.__queue_list = []
        self.__sem = Semaphore(0)

    @synchronized
    def add(self, item):
        self.__queue_list.append(item)
        self.__sem.release()

    @synchronized
    def pop(self, timeout=120):
        put = self.__sem.acquire(timeout=timeout)
        if put:
            p = self.__queue_list.pop(0)
            return p
        raise TimeoutError('Semaphore timeout.')

    def __str__(self):
        return str(self.__queue_list)

    def __repr__(self):
        return str(self)
