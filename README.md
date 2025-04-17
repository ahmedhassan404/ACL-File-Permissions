# ACL Permission Checker in C

This project implements an **Access Control List (ACL)** permission checker in C, simulating UNIX-style file access control with support for extended ACLs, named users, named groups, and permission masks.

## Features

- ACL entries for user owner, group owner, others, named users, named groups, and masks
- Permission bits: Read (r), Write (w), Execute (x)
- Load ACL entries from a file or use default values
- Check access permissions based on effective UID and GID
- Print current ACL entries

## File Structure

- `main.c`: The main C file containing all logic for ACL handling and permission checking.
- `acl.txt` *(optional)*: Input file to load ACL entries from.

## How It Works

1. The program prompts the user to choose between loading ACL from a file or using a default ACL.
2. It displays all ACL entries.
3. It asks for an effective UID, GID, and desired permissions (e.g., `rw`, `rwx`).
4. It checks whether access should be granted based on ACL rules.

## ACL File Format (`acl.txt`)

Each line should be in the format:

```
user:<username>:<permissions>
group:<groupname>:<permissions>
user::rw
group::r
mask::rw
other::r
```

### Example

```
user::rw
user:john:rw
group::rw
group:devs:r
mask::rw
other::
```

## Building the Project

Use `gcc` to compile the program:

```sh
gcc -o acl_checker main.c
```

## Running the Program

```sh
./acl_checker
```

## Sample Run

```
Do you want to load ACL from file? (y/n): n
ACL Entries:
Entry 0: Type=USER_OWNER, ID=N/A, Permissions=rw-
Entry 1: Type=NAMED_USER, ID=1001, Permissions=rw-
...
Enter effective UID (eUID): 1001
Enter effective GID (eGID): 2001
Enter desired permission (r, w, x, rw, rx, wx, rwx): rw

Access GRANTED!
```

##

