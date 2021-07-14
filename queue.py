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

    def __init__(self, sem_timeout=120):
        self.__queue_list = []
        self.__sem = Semaphore(0)
        self.__sem_timeout = sem_timeout

    @synchronized
    def add(self, item):
        self.__queue_list.append(item)
        self.__sem.release()

    @synchronized
    def pop(self):
        put = self.__sem.acquire(timeout=self.__sem_timeout)
        if put:
            p = self.__queue_list.pop(0)
            return p
        raise TimeoutError('Semaphore timeout.')

    def __str__(self):
        return str(self.__queue_list)

    def __repr__(self):
        return str(self)
