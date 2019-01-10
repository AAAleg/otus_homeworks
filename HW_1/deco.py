#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import update_wrapper


def disable(func):
    '''
    Disable a decorator by re-assigning the decorator's name
    to this function. For example, to turn off memoization:

    >>> memo = disable

    '''
    return func


def decorator(dec):
    '''
    Decorate a decorator so that it inherits the docstrings
    and stuff from the function it's decorating.
    '''
    def wrapper(func):
        return update_wrapper(dec(func), func)

    update_wrapper(wrapper, dec)
    return wrapper


@decorator
def countcalls(func):
    '''Decorator that counts calls made to the function decorated.'''
    def wrapper(*args):
        wrapper.calls = getattr(wrapper, 'calls', 0) + 1
        return func(*args)

    return wrapper


@decorator
def memo(func):
    '''
    Memoize a function so that it caches all return values for
    faster future lookups.
    '''
    def wrapper(*args):
        update_wrapper(wrapper, func)
        if not getattr(wrapper, 'cache', None):
            wrapper.cache = {}
        if args in wrapper.cache:
            return wrapper.cache[args]
        else:
            result = wrapper.cache[args] = func(*args)
            return result
    return wrapper


@decorator
def n_ary(func):
    '''
    Given binary function f(x, y), return an n_ary function such
    that f(x, y, z) = f(x, f(y,z)), etc. Also allow f(x) = x.
    '''

    def wrapper(x, *args):
        return x if not args else func(x, wrapper(*args))
    return wrapper


def trace(spaces='____'):
    '''Trace calls made to function decorated.

    @trace("____")
    def fib(n):
        ....

    >>> fib(3)
     --> fib(3)
    ____ --> fib(2)
    ________ --> fib(1)
    ________ <-- fib(1) == 1
    ________ --> fib(0)
    ________ <-- fib(0) == 1
    ____ <-- fib(2) == 2
    ____ --> fib(1)
    ____ <-- fib(1) == 1
     <-- fib(3) == 3

    '''

    @decorator
    def top_wrapper(func):
        def wrapper(*args):
            signature = '{0}({1})'.format(func.__name__, ', '.join(map(repr, args)))
            indent = trace.level * spaces
            print '{0} --> {1}'.format(indent, signature)
            trace.level += 1
            try:
                result = func(*args)
                indent = (trace.level - 1) * spaces
                print '{0} <-- {1} == {2}'.format(indent, signature, result)
            finally:
                trace.level -= 1
            return result
        trace.level = 0

        return wrapper
    return top_wrapper


@memo
@countcalls
@n_ary
def foo(a, b):
    return a + b


@countcalls
@memo
@n_ary
def bar(a, b):
    return a * b


@countcalls
@trace('####')
@memo
def fib(n):
    """Some doc"""
    return 1 if n <= 1 else fib(n-1) + fib(n-2)


def main():
    print foo(4, 3)
    print foo(4, 3, 2)
    print foo(4, 3)
    print "foo was called", foo.calls, "times"

    print bar(4, 3)
    print bar(4, 3, 2)
    print bar(4, 3, 2, 1)
    print "bar was called", bar.calls, "times"

    print fib.__doc__
    fib(3)
    print fib.calls, 'calls made'


if __name__ == '__main__':
    main()
