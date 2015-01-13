#!/usr/bin/env python
from distutils.core import setup, Extension

setup(name="adclient",
      version="1.0",
      description = "Active Directory manipulation tool",
      author = "Oleg Palij",
      author_email = "o.palij@gmail.com",
      py_modules=["adclient"],
      ext_modules=[Extension("_adclient", ["adclient_wrapper_python.cpp"],
                   include_dirs=["/usr/local/include", "/usr/include"],
                   library_dirs=["/usr/local/lib", "/usr/lib"],
                   libraries=["ldap", "adclient"],
                   extra_compile_args=["-g", "-O0", "-Wall"]
                            )
                  ]
     )
