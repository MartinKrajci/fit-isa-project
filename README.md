# Network Applications and Network Administration
## DNS resolver
This tool can be used to resolve different types of DNS queries.

## Build
Use `make` command to build this project.

## Run
Tool require two arguments and four arguments are optional.
```bash
$ ./dns -s dns_server ip_or_name [-x] [-r] [-p port] [-6]
```
where:

### -x
Use for reverse query.

Example:
```bash
$ ./dns -s 8.8.8.8 140.82.121.4 -x 
Authoritative: No, Recursive: No, Truncated: No
Question section (1)
 4.121.82.140.in-addr.arpa., PTR, IN
Answer section (1)
 4.121.82.140.in-addr.arpa., PTR, IN, 3312, lb-140-82-121-4-fra.github.com.
Authority section (0)
Additional section (0)
```

### -r
Use for recursive query.

Example:
```bash
$ ./dns -s 1.1.1.1 github.com -r
Authoritative: No, Recursive: Yes, Truncated: No
Question section (1)
 github.com., A, IN
Answer section (1)
 github.com., A, IN, 23, 140.82.121.4
Authority section (0)
Additional section (0)
```

### -p
Use to specify different port on DNS server. Default is 53.

Example:
```bash
$ ./dns -s 8.8.8.8 github.com -p 53
Authoritative: No, Recursive: No, Truncated: No
Question section (1)
 github.com., A, IN
Answer section (1)
 github.com., A, IN, 40, 140.82.121.4
Authority section (0)
Additional section (0)
```

### -6
Use if you expect IPv6 address as an answer.

Example:
```bash
./dns -s 8.8.8.8 google.com -6 -r
Authoritative: No, Recursive: Yes, Truncated: No
Question section (1)
 google.com., AAAA, IN
Answer section (1)
 google.com., AAAA, IN, 295, 2a00:1450:4014:80a::200e
Authority section (0)
Additional section (0)
```