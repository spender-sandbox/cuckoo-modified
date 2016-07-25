@doomedraven TODO: remove API.py Iocs function, bcuz duplicate code

This PR summarizes improved functionality of a distributed cuckoo configuration, allowing processing power to be extended by creating several cuckoo nodes, that are linked and operated by a leader.

## Features

### dist.py
- `dist.py` is a standalone backend application that manages all tasks and nodes. Is run on the leader.
- Fetches new tasks from *main* cuckoo db (submitted via web gui or django api). 
- Tasks can be submitted to `dist.py` api directly if it is exposed to the users.
- Assigns tasks to nodes that only have available tags to process these tasks.
- Assigns tasks by highest priority and lowest ID number.
- After task is processed on *slave* stripped (w/o keys > 16mb) report from mongo, report.json and screenshots are transferred as a gzipped archive from *slave* to *leader*. `dist.py` then inserts this information into the *mongo* database. Therefore not required to run any sort of processing module on leader.
- Other task data such as *dropped files, memdump, etc.* is transferred in the background on a separate thread for each task using the `Retriever` class. 
- All task data can be removed from the slave machines. 
- Can automatically mark nodes as *dead* if they have not been responding to `x` number of status API calls.
- Stores samples in the *binary* folder after they are processed and creates symlink to `/analyses/id/binary`
- Allows `htaccess` to be set up on slaves api so that only the leader `dist.py` can submit tasks there.
- Updated API call to update node properties
- Has functions to *update* existing VM's on *slave* nodes, *delete* VM's from *slave* nodes for maintenance without disabling the whole node. 

### api.py
- Is run on the *slave* nodes, communicates with `dist.py`
- Call to delete VM on slave node
- Can be run with uwsgi to be properly threaded for background downloads of task data.

### Updated documentation

## Summary

We are happy with out results, performance is improved and we are testing under high loads now, on localnetwork and non local network set ups. Please tell us what you think, we would really like to get this accepted.

