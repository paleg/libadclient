#!/usr/bin/env python
from distutils.core import setup, Extension
import sys

wrapper = "adclient_wrapper_python{0}.cpp".format(sys.version_info[0])

setup(name="adclient",
      version="1.0",
      description = "Active Directory manipulation tool",
      author = "Oleg Palij",
      author_email = "o.palij@gmail.com",
      py_modules=["adclient"],
      ext_modules=[Extension("_adclient", [wrapper],
                   include_dirs=["/usr/local/include", "/usr/include"],
                   library_dirs=["/usr/local/lib", "/usr/lib"],
                   libraries=["ldap", "adclient"],
                   extra_compile_args=["-g", "-O0", "-Wall"]
                            )
                  ]
     )
