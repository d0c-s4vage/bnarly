* [Overview] (#bnarly)
* [API] (#bnarly-api)
* [API Index] (#bnarly-api-index)

---

bNarly
======

bNarly (browser narly) is a browser exploitation/exploration tool. bNarly is essentially a windbg <--> javascript bridge.

A brief overview of its use can be seen here: http://www.youtube.com/watch?v=7r4A29NwlX4

Browser Compatibility
---------------------

bNarly will work on *at least* the following browser versions

* IE 8,9,10,11
* Firefox >= 20

windbg/js bridge
----------------

The javascript/windbg bridge works by setting a breakpoint on the `Math.min` function. `Math.min` is specifically chosen because it is a variable arity function (can accept a variable number of arguments).

With the breakpoint in place, `Math.min` essentially takes the form:
``` javascript
WINDBG_CMD_EVAL = 111111;
WINDBG_LOGGING  = 222222;
function Math.min(in type, in logMsg_or_cmdsToEval, out output, in objRef) {
  // windbg command evaluation
  if(type == WINDBG_CMD_EVAL) {
    if(objRef) {
      @$t0 = &objRef;
    }
    
    var tmpOutput = windbgEval(logMsg_or_cmdsToEval);
    
    if(output) {
      *output = tmpOutput;
      continueExecution();
    }
  
  // simple logging
  } else if(type == WINDBG_LOGGING) {
    echo(logMsg_or_cmdsToEval);
    continueExecution();
  
  } else {
    continueExecution();
  }
}
```

Note that execution must explicitly be continued if not requesting the output of a command.

bNarly API
==========
Configuration
-------------

#### `setMainWindow(win)`

Set the window that the debugger will be attached to.

#### `setUseSymbolCache(trueFalse)`

Set whether a symbol cache should be used

#### `populateSymbolCache()`

Populate the symbol cache with vftable symbols from "popular" browser
modules (eg `mshtml!*vftable*` and `jscript9!*vftable*`)


Utils
-----

#### `int3()`

Force execution to pause

#### `log(msg)`

Print the message and continue. This method should be safe for ANY message content
without needing to escape anything.

Setup
-----

#### `getWindbgBreakpoint()`

Return the breakpoint for the current browser. If a breakpoint for the current
version has not been explicitly defined, return the default breakpoint for
the browser family.

#### `getSymbolServerLocations()`

Return the symbol server locations that should be in `.sympath` in order for
bNarly to work correctly.

#### `getBrowserVersion()`

Return a string that represents the version of the browser. Eg: 10_x86

#### `getBrowserName()`

Return the name/family of the browser. Eg: MSIE

#### `isConnected()`

Return true/false whether a debugger is connected and the breakpoint appears
to be functioning

Candy
-----

#### `evalExpr(expression)`

Evaluate the given expression and return the result. The result will *always*
be a number. This is the same as running the windbg command `? <expression>`.

#### `startHeapTracking()`

Begin tracking heap allocs/frees. Retrieve tracked heap events by calling `stopHeapTracking()`

#### `stopHeapTracking()`

Stop tracking heap allocs/frees. Returns an object of the form:

```
{
	timeline: [...],
	unAllocatedFrees: {...},
	unFreedAllocs: {...}
}
```

* `timeline` is an array of heap events, in the order they occurred.
* `unAllocatedFrees` is an object with keys being addresses that have been freed but were not allocated after `startHeapTracking()` was called. The values are heap events.
* `unFreedAllocs` is an object with keys being addresses that have been allocated and were not freed since `startHeapTracking()` was called. The values are heap events.

A heap event is of the form:

```
{
	type: FREE or ALLOC,
	addr: address,
	(size: allocation size)?,
	(heap: heap allocation belongs to)?,
	(firstPtr: value of poi(addr))?
}
```

#### `getObjectPtr(obj, isOnlyObjName)`

Return a pointer to the given object. If `isOnlyName` is true, the obj is assumed to be a string
and will be evaluated in the window that `setMainWindow(win)` was set to.


#### `getObjectSize(ptr)`

Return the size of the memory allocation referenced by ptr. An
object is returned with at least the two members:

`{base: <addr>, size: <size>}`

More members might be added to the object, depending on which allocator
is used.

If the memory allocation size/base could not be determined, null
is returned.

Symbol Resolution
-----------------

#### `getSymbol(addr)`

Return the symbol at the provided address. Returns "" if no
matching symbol is found.

#### `getSymbols(addrs)`

Return the symbols for each address in addrs in an object of the form
`{addr: symbol, ...}`. If no matching symbol is found, the symbol value
will be "".

Breakpoints
-----------

#### `setBreakpoint(addr, commands, type)`

Sets a breakpoint at `addr` (may also be a symbol). Default breakpoint
`type` is `bp`, may also pass in `bu` or `bm`.

The `commands` argument is an unescaped string of commands. The commands
will automatically be escaped.

Returns the breakpoint id that can be passed to `clearBreakpoint(bpId)` to
remove the breakpoint.

#### `clearBreakpoint(bpId)`

Clear the breakpoint associated with `bpId`

Memory Read
-------------

### string functions

#### `da(address, brokenUp, limit)`

Return the string referenced by `address`.

If `brokenUp` is true, an array of objects of the form `{addr:<address>, val:<val>}` will
be returned.

`limit` limits the length of the string. Eg: `da <addr> L?0n<limit>`

#### `du(address, brokenUp, limit)`

Return the unicode string referenced by `address`.

If `brokenUp` is true, an array of objects of the form `{addr:<address>, val:<val>}` will
be returned.

`limit` limits the length of the unicode string. Eg: `du <addr> L?0n<limit>`

### option to resolve symbols

#### `dd(address, num, symLookup)`

Return an array of objects containing the dword values and symbols at
each address:

`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`

#### `dp(address, num, symLookup)`

Return an array of objects containing the pointer-sized values and
symbols at each address:

`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`

#### `ddp(address, num, symLookup)`

Return an array of objects containing the dword-sized values and
symbols at each	address:

`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`

If `symLookup` is true, an attempt will be made to resolve symbols. The
windbg command `ddp` by default will display the dereferenced pointer and
the memory at the resulting location. Any results from `symLookup` will
override the symbols from the windbg output of `ddp`.

#### `dpp(address, num, symLookup)`

Return an array of objects containing the pointer-sized values and
symbols at each	address:

`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`


If `symLookup` is true, an attempt will be made to resolve symbols. The
windbg command `dpp` by default will display the dereferenced pointer and
the memory at the resulting location. Any results from `symLookup` will
override the symbols from the windbg output of `dpp`.

### single memory access

#### `by(address)`

Return the byte at the given address

#### `wo(address)`

Return the word at the given address

#### `dwo(address)`

Return the dword at the given address

#### `qwo(address)`

Return the qword at the given address

#### `poi(address)`

Return the pointer at the given address

### mass raw memory dump

#### `db(address, num)`

Return an array of objects representing `num` bytes starting at `address`.

Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`

#### `bytes(address, num)`

Return an array of objects representing `num` bytes starting at `address`.

Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`

#### `words(address, num)`

Return an array of objects representing `num` words starting at `address`.

Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`

#### `dwords(address, num)`

Return an array of objects representing `num` dwords starting at `address`.

Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`

#### `qwords(address, num)`

Return an array of objects representing `num` qwords starting at `address`.

Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`

Memory Write
------------

#### `eb(/*addr, val1, val2, ...*/)`

Overwrite bytes at `addr` with values `val1`, `val2`, ...

#### `ew(/*addr, val1, val2, ...*/)`

Overwrite words at `addr` with values `val1`, `val2`, ...

#### `ed(/*addr, val1, val2, ...*/)`

Overwrite dwords at `addr` with values `val1`, `val2`, ...

#### `eq(/*addr, val1, val2, ...*/)`

Overwrite qwords at `addr` with values `val1`, `val2`, ...

Core
----

#### `run(/*cmd1, cmd2, ...*/)`

Run the given command. Do not return the output. Code execution must be
explicitly resumed with `g`.

#### `evalRaw(/*cmd1, cmd2, ...*/)`

Run the given commands found in arguments and return the output. Code
execution will automatically be resumed.

#### `shell(cmd)`

Run `cmd` without waiting for the created process to exit

bNarly API Index
================

* [Configuration] (#configuration)
    * [setMainWindow] (#setmainwindowwin)
    * [setUseSymbolCache] (#setusesymbolcachetruefalse)
    * [populateSymbolCache] (#populatesymbolcache)
* [Utils] (#utils)
    * [int3] (#int3)
    * [log] (#logmsg)
* [Setup] (#setup)
    * [getWindbgBreakpoint] (#getwindbgbreakpoint)
    * [getSymbolServerLocations] (#getsymbolserverlocations)
    * [getBrowserVersion] (#getbrowserversion)
    * [getBrowserName] (#getbrowserName)
    * [isConnected] (#isconnected)
* [Candy] (#candy)
    * [evalExpr] (#evalexprexpression)
    * [startHeapTracking] (#startheaptracking)
    * [stopHeapTracking] (#stopheaptracking)
    * [getObjectPtr] (#getobjectptrobj-isonlyobjname)
    * [getObjectSize] (#getobjectsizeptr)
* [Symbol Resolution] (#symbol-resolution)
    * [getSymbol] (#getsymboladdr)
    * [getSymbols] (#getsymbolsaddrs)
* [Breakpoints] (#breakpoints)
    * [setBreakpoint] (#setbreakpointaddr-commands-type)
    * [clearBreakpoint] (#clearbreakpointbpid)
* [Memory Read] (#memory-read)
    * 	// string functions
    * [da] (#daaddress-brokenup-limit)
    * [du] (#duaddress-brokenup-limit)
    * 	// option to resolve symbols
    * [dd] (#ddaddress-num-symlookup)
    * [dp] (#dpaddress-num-symlookup)
    * [ddp] (#ddpaddress-num-symlookup)
    * [dpp] (#dppaddress-num-symlookup)
    * 	// single memory access
    * [by] (#byaddress)
    * [wo] (#woaddress)
    * [dwo] (#dwoaddress)
    * [qwo] (#qwoaddress)
    * [poi] (#poiaddress)
    * 	// raw memory dump
    * [db] (#dbaddress-num)
    * [bytes] (#bytesaddress-num)
    * [words] (#wordsaddress-num)
    * [dwords] (#dwordsaddress-num)
    * [qwords] (#qwordsaddress-num)
* [Memory Write] (#memory-write)
    * [eb] (#ebaddr-val1-val2-)
    * [ew] (#ewaddr-val1-val2-)
    * [ed] (#edaddr-val1-val2-)
    * [eq] (#eqaddr-val1-val2-)
* [Core] (#core)
    * [run] (#run)
    * [evalRaw] (#evalrawcmd1-cmd2-)
    * [shell] (#shell)

