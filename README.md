# kube-audit-log-enricher

[![codecov](https://codecov.io/gh/pjbgf/kube-audit-log-enricher/branch/master/graph/badge.svg)](https://codecov.io/gh/pjbgf/kube-audit-log-enricher)
![build](https://github.com/pjbgf/kube-audit-log-enricher/workflows/go/badge.svg)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

## Overview

This project is a `DaemonSet` that once deployed will process the host syslog maching any seccomp entries
and enrich them with Kubernetes information (namespace, pod and container names).

Original log entry:
```
[252130.031583] audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000
```

Enriched entry:
```
audit(1611996299.149:466250) type=seccomp node=kube-worker1 pid=20923 ns=default pod=my-pod c=container1 exe=/init syscall=epoll_pwait
```

## Deploy

```bash
kubectl apply -f https://raw.githubusercontent.com/pjbgf/kube-audit-log-enricher/master/deploy/all-in-one.yaml
```

## Support

Container Runtime: `CRI-O`
Linux Distribution: `Ubuntu`

## License

This application is licensed under the MIT License, you may obtain a copy of it [here](LICENSE).