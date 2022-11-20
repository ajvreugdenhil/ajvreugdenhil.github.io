---
layout: post
title: Tool recommendations & configs
categories: Tools
published: false
---

## shoutout to non-security tools

- todoist
- umatrix, httpseverywhere

## My kali config

### Fish

```bash
https://software.opensuse.org/download.html?project=shells%3Afish%3Arelease%3A3&package=fish
cat /etc/shells
chsh
```

~/.config/fish/functions/fish_greeting.fish

```plaintext
function fish_greeting
        set_color brgreen
        echo (whoami)@(hostname):(pwd)
        set_color normal
end
```

~/.config/fish/functions/fish_prompt.fish

```plaintext
function fish_prompt
        set_color brgreen
        echo (prompt_pwd)(set_color normal)' > '
end
```

### VSC

```bash
https://code.visualstudio.com/Download
sudo apt install ./<file>.deb
```

### Gitkraken

```bash
wget https://release.gitkraken.com/linux/gitkraken-amd64.deb
sudo dpkg -i gitkraken-amd64.deb
```

### Other tools

```bash

sudo apt install tree

```

### angr

reference: <https://www.youtube.com/watch?v=RCgEIBfnTEI>

```bash
sudo apt install python3-venv
```

```bash
cd ~/ctf/ourchallenge
python3 -m venv angr
ls angr/
zsh
source angr/bin/activate
pip3 install angr
```

Then use for example [template](angr_template.md) anywhere

### debugger

- gdb config

### Disassemblers

- <https://cutter.re/>
- <https://github.com/radareorg/radare2>
- <https://www.hopperapp.com/>
- <https://binary.ninja/>
- Ghidra
- IDA

- <http://www.ollydbg.de/>
- dnspy

- auto save on focus change
- drawio
- todo
- markdown aio
- markdown lint
