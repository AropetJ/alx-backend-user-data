# 0x03. User authentication service

![userdata image](./userdata.jpg)

In the industry, you should not implement your own authentication system and use a module or framework that doing it for you (like in Python-Flask: [Flask-User](https://intranet.alxswe.com/rltoken/9nVfotMI_1zpEzihMzBeTA)). Here, for the learning purpose, we will walk through each step of this mechanism to understand it by doing.

## Resources
### Read or watch:
- [Flask documentation](https://intranet.alxswe.com/rltoken/lKExyvivrrW4eh0eI8UV6A)
- [Requests module](https://intranet.alxswe.com/rltoken/py7LuuD1u2MUwcaf8wnDzQ)
- [HTTP status codes](https://intranet.alxswe.com/rltoken/cj-mc5ZHp_KyXn1yikHC0A)

## Learning Objectives
At the end of this project, you are expected to be able to [explain](https://intranet.alxswe.com/rltoken/oAqmZmipBdjCcfI5QqyFXA) to anyone, without the help of Google:
- How to declare API routes in a Flask app
- How to get and set cookies
- How to retrieve request form data
- How to return various HTTP status codes

## Requirements
- Allowed editors: `vi, vim, emacs`
- All of your files will be interpreted/compiled on Ubuntu 18.04 LTS using python3 (version 3.7)
- All of your files should end with a new line
- A `README.md` file, at the root of the folder of the project, is mandatory
- The first line of all your files should be exactly `#!/usr/bin/env python3`
- Your code should use the `pycodestyle` style (version 2.5)
- All your modules should have documentation (`python3 -c 'print(__import__("my_module").__doc__)'`)
- All your classes should have documentation (`python3 -c 'print(__import__("my_module").MyClass.__doc__)'`)
- All your functions and methods should have documentation (`python3 -c 'print(__import__("my_module").my_function.__doc__)'` and `python3 -c 'print(__import__("my_module").MyClass.my_function.__doc__)'`)
- A documentation is not a simple word, it’s a real sentence explaining what’s the purpose of the module, class or method (the length of it will be verified)
- All your functions and coroutines must be type-annotated.

## Setup
You will need to install `bcrypt`

```bash
pip3 install bcrypt
```
