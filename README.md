Firefox One-way Sync
====================

This script uses Mozilla Services API to synchronize data from
one firefox account to another, **one-way only**.
Useful for work -> life account synchronize.

By default it works with history and tabs. You can modify the
code to support others (addons, bookmarks, forms, etc,.)


How to
------

Run this on a crontab:

```
python main.py from@example.com:password-0 to@example.com:password-1
```

On each run, it would try to synchronize new data (from last run) from
`from@example.com` to `to@example.com`.
Running it multiple times should be fine. No duplicates will be created.

Note that this script would save *.pickle in current directory,
containing session keys and last modified time.


Read more
---------

- [Mozilla Services Storage API](https://moz-services-docs.readthedocs.io/en/latest/storage/apis-1.5.html#api-instructions)
- [Mozilla Services Object Format](https://moz-services-docs.readthedocs.io/en/latest/sync/objectformats.html#history)
- https://github.com/mozilla-services/syncclient
- https://github.com/mozilla-services/syncclient/issues/30#issuecomment-280517782
- https://github.com/mozilla-services/syncclient/issues/28#issuecomment-386781775
