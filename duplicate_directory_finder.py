""" Prints paths that appear to be duplicates.


IMPLEMENTATION NOTES:

Each item is a tuple of 3 parts:
0: Absolute path of parent directory
1: The name of the file/irectory
2: A hash of the contents or children
3: Max depth of children (files are 0)
"""
from __future__ import print_function

import hashlib
import os
import sys
import time
import threading

BUF_SIZE = 65536

_cur_bad_file_sequence = 0

_progress_checker = None


class ProgressChecker(threading.Thread):

    def __init__(self):
        super(ProgressChecker, self).__init__()
        self.daemon = True
        self.is_done = False
        self.status = '???'
        self.cur_path = ''

    def run(self):
        while not self.is_done:
            time.sleep(8)
            print('{} {}'.format(self.status, self.cur_path))


def get_bad_file_hash():
    global _cur_bad_file_sequence
    # fake_hash = 'ERR_{}'.format(_cur_bad_file_sequence)
    fake_hash = 'ERR'
    _cur_bad_file_sequence += 1
    return fake_hash


def hash_file(file_path):
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(BUF_SIZE)
                if not data:
                    break
                sha1.update(data)
        return '{}'.format(sha1.hexdigest())
    except OSError:
        print('WARNING Cannot access file: {}'.format(file_path))
        return get_bad_file_hash()


def hash_dir(children):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    for child in children:
        child_bytes = child.encode('utf8', errors='backslashreplace')
        md5.update(child_bytes)
        sha1.update(child_bytes)
    return '{}_{}'.format(md5.hexdigest(), sha1.hexdigest())


def walk_directory(dir_path):
    items = []
    for child in sorted(os.listdir(dir_path)):
        child_path = os.path.join(dir_path, child)
        _progress_checker.cur_path = child_path
        if os.path.isdir(child_path):
            try:
                child_items = walk_directory(child_path)
                dir_hash = hash_dir(['{}:{}'.format(item[1], item[2])
                                     for item in child_items])
            except OSError:
                print('WARNING Cannot access dir: {}'.format(child_path))
                child_items = []
                dir_hash = get_bad_file_hash
            # [-1] makes it so that empty directories have no depth,
            # improving performance and making sure that they don't all
            # show up as matches for each other.
            depth = max([-1] + [item[3] for item in child_items]) + 1
            items.append((dir_path, child, dir_hash, depth))
            items.extend(child_items)
        else:
            file_hash = hash_file(child_path)
            items.append((dir_path, child, file_hash, 0))
    return items


def get_item_full_path(item):
    return os.path.join(item[0], item[1])


def find_duplicates(items):
    items = sorted(items, key=lambda i: (i[3], i[2], i[1]), reverse=True)
    seen = {}
    dupe_src = set()
    dupe_trg = set()
    for item in items:
        _progress_checker.cur_path = get_item_full_path(item)
        key = (item[1], item[2])
        if not item[3]:
            continue
        elif key in seen:
            dup_from = seen[key]
            print('DUPLICATE: {}'.format(get_item_full_path(item)))
            print('  (from {}'.format(get_item_full_path(dup_from)))
            dupe_trg.add(item)
            dupe_src.add(dup_from)
        elif any([item[0].startswith(d[0]) for d in dupe_trg]):
            # Skip because it's a child of something found to be
            # a duplicate
            continue
        else:
            seen[key] = item
            # print('Adding {}'.format(get_item_full_path(item)))
    return dupe_src, dupe_trg


def run(root_dir_path):
    _progress_checker.start()
    _progress_checker.status = 'Indexing'
    print('Indexing all files in {}'.format(root_dir_path))
    print()
    items = walk_directory(root_dir_path)
    print()
    print('Indexed {} files'.format(len(items)))
    print()
    _progress_checker.status = 'Checking'
    find_duplicates(items)
    print()
    print('Duplicate search complete!')
    _progress_checker.is_done = True


if __name__ == '__main__':
    _progress_checker = ProgressChecker()
    root_dir_path = sys.argv[1]
    run(root_dir_path)
