---
title: Git Cheatsheet
tags:
  - Cheatsheet
  - Git
date: 2024-03-05
---

> It’s quite easy to use git clone or git pull/push to manage open-source code, but git can do much more than this.

## Setting Up Proxy

It sometimes suffers when using git commands in certain countries, the following code shows how to set up ssh proxy for git commands:

```nix
{ pkgs, lib, ... }: {
  home = {
    file.".ssh/config".text = ''
      Host github.com
          Hostname ssh.github.com
          Port 443
          User git
          ProxyCommand ${pkgs.netcat}/bin/nc -v -x host.orb.internal:6153 %h %p
      Host github.com
          port 22
          User git
          HostName github.com
          PreferredAuthentications publickey
          ProxyCommand ${pkgs.netcat}/bin/nc -v -x host.orb.internal:6153 %h %p
    '';
  };
}
```

---

## Sparse Checkout

Sparse checkout is used to checkout only selected files or directories instead of the entire repository, which is especially helpful when managing large projects. [1]

```bash
git clone --filter=blob:none --no-checkout <repository-url>
cd <repository-name>
git sparse-checkout init --cone
git sparse-checkout set <path1> <path2> ...
git checkout
```

Let’s take `ctf-wiki/ctf-challenges` as an example:

```bash
git clone --filter=blob:none --no-checkout git@github.com:ctf-wiki/ctf-challenges.git
cd ctf-challenges/
git sparse-checkout init --cone
git sparse-checkout set pwn blockchain
git checkout
```

---

## Stop Leaking Secrets

I’m going to introduce a useful light tool here: https://github.com/gitleaks/gitleaks[2][3], which can alert you and stop your commit when the result of `git log -p` might contain sensitive keys.

It’s simple to install and use it as a command line tool, having brew package for mac users and nixpkgs for my NixOS.

Its default config is strict enough for me so I won’t talk about custom configuration here.

### Pre-commit hook

It provides python script for pre-commit-hook, with reference to [https://github.com/gitleaks/gitleaks/blob/master/scripts/pre-commit.py](https://github.com/gitleaks/gitleaks/blob/master/scripts/pre-commit.py):

```bash
#!/usr/bin/env python3
"""Helper script to be used as a pre-commit hook."""
import os
import sys
import subprocess

def gitleaksEnabled():
    """Determine if the pre-commit hook for gitleaks is enabled."""
    out = subprocess.getoutput("git config --bool hooks.gitleaks")
    if out == "false":
        return False
    return True

if gitleaksEnabled():
    exitCode = os.WEXITSTATUS(os.system('gitleaks protect -v --staged'))
    if exitCode == 1:
        print('''Warning: gitleaks has detected sensitive information in your changes.
To disable the gitleaks precommit hook run the following command:

    git config hooks.gitleaks false
''')
        sys.exit(1)
else:
    print('gitleaks precommit disabled\
     (enable with `git config hooks.gitleaks true`)')
```

Apply this to your own project by simply copying the above code to `./.git/hooks/pre-commit` and `chmod +x ./.git/hooks/pre-commit`.

## Erase Previous Commits

It seems helpful to know how to erase all commit records when you find some secrets are leaked.

```bash
git checkout --orphan latest_branch
git add -A
git commit -am "Initialize repository"
git branch -D main
git branch -m main
git push -f origin main
```

---

## References

\[1\] [ChatGPT](http://chat.openai.com)

\[2\] [Stop Leaking Secrets . _Zach_](https://blog.gitleaks.io/stop-leaking-secrets-configuration-2-3-aeed293b1fbf)

\[3\] [Protect and discover secrets using Gitleaks . _gitleaks_](https://github.com/gitleaks/gitleaks)
