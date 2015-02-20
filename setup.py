from distutils.core import setup, Extension

pluck_hash_module = Extension('pluck_hash',
                               sources = ['pluckmodule.c'],
                               include_dirs=['.'])

setup (name = 'pluck_hashs',
       version = '1.0',
       description = 'Bindings for proof of work used by pluck hash',
       ext_modules = [pluck_hash_module])
