kit - a simple type system
==========================

kit is a simple library for a type system, inspired by [llib][1]. 
it can be used to simplifiy developing. kit offers:
  - ref-counted object/array
  - pointer-compare symbol
  - array of refs (refarray) support
  - a object pool implement
  - a hashtable implement

routines ends with '_' are unchecked version. all objects newed by
kit are recorded, and function such as kit_retain() will check
whether a void* pointer is from kit. using kit_retain_() means you
sure the pointer is really from kit.

kit is a single header library. just add kit.h to your project, and
add `KIT_IMPLEMENTATION` before `#include "kit.h"` to include
implement of kit library.

see `kit_test.c` for how to use this library.

[1]: https://github.com/stevedonovan/llib
