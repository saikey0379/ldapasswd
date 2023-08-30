ldapasswd:  A tool that persists LDAP user and group information into Linux configuration, enabling effective usage of user and group IDs in a containerized state."

### Resolve the following issue
- groups: cannot find name for group ID 10000."
- sudo apt-get error
- sudo yum install error
## Getting Started
```bash
git clone https://github.com/saikey0379/ldapasswd.git
cd ldapasswd
export GOBIN=`pwd`/bin
go install .
bin/ldapasswd
```
####  Usage of Docker Containers.
``` shell
docker run -it -u 10000:10000 --group-add 20000  image_name

bash-4.4$ id                                                                                          
uid=10000(10000) gid=10000(10000) groups=10000(10000),20000
...
...
...
docker run -it -u 10000:10000 --group-add 20000 -v /etc/ldap_passwd:/etc/passwd -v /etc/ldap_shadow:/etc/shadow -v /etc/ldap_group:/etc/group image_name

bash-4.4$ id                                                                                          
uid=10000(test) gid=10000(test) groups=10000(test),20000(test1)
```
#### Usage of Kubernetes.
```yaml
      securityContext:
        runAsGroup: 10000
        runAsUser: 10000
        supplementalGroups:
        - 20000
...
...
...
      volumeMounts:
        - name: passwd
          mountPath: /etc/passwd
        - name: shadow
          mountPath: /etc/shadow
        - name: group
          mountPath: /etc/group
    volumes:
    - name: "passwd"
      hostPath:
        path: "/etc/ldap_passwd"
    - name: "shadow"
      hostPath:
        path: "/etc/ldap_shadow"
    - name: "group"
      hostPath:
        path: "/etc/ldap_group"
```