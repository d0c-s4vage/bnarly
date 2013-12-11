var bnarly = (function() {
	
	var bInfo = (function(){
		var N= navigator.appName, ua= navigator.userAgent, tem;
		var M= ua.match(/(opera|chrome|safari|firefox|msie)\/?\s*(\.?\d+(\.\d+)*)/i);
		if(M && (tem= ua.match(/version\/([\.\d]+)/i))!= null) M[2]= tem[1];
		M= M? [M[1], M[2]]: [N, navigator.appVersion, '-?'];
		M = {
			"name": M[0],
			"version": M[1],
			"type": (window.navigator.platform.indexOf("64") == -1 ? "x86" : "x64")
		};
		// stupid userAgent change with IE11
		if(M["name"] == "Netscape" && window.navigator.userAgent.indexOf("Trident") != -1) {
			M["name"] = "MSIE";
		}
		return M;
	})();

	if(!String.prototype.trim) {  
		String.prototype.trim = function () {  
			return this.replace(/^\s+|\s+$/g,'');  
		};  
	}

	if (!Array.prototype.indexOf)
	{
		Array.prototype.indexOf = function(elt /*, from*/) {
			var len = this.length >>> 0;

			var from = Number(arguments[1]) || 0;
			from = (from < 0)? Math.ceil(from): Math.floor(from);
			if (from < 0) {
				from += len;
			}

			for (; from < len; from++) {
				if (from in this &&	this[from] === elt) {
					return from;
				}
			}
			return -1;
		};
	}

	function argsToArray(args) {
		// assumes commands is actually an arguments object
		if(typeof args == "object") {
			args = Array.prototype.slice.call(args, 0 );
		}
		return args;
	}

	function toInt(str) {
		str = str.replace("`", "");
		var addr = parseInt(str, 16);
		return addr;
	}

	/*
	Convert the given object to a windbg value. If the argument is a string,
	it is assumed that the obj is a symbol or other non-int resolvable
	value (eg @$scopeip, @$t3, etc). 
	*/
	function toWAddr(obj) {
		if(typeof obj == "string") {
			return obj;
		} else if(typeof obj == "number") {
			return "0n" + obj;
		} else {
			throw "Unrecognized address object!";
		}
	}

	function getKeys(obj){
		var keys = [];
		for(var key in obj){
			keys.push(key);
		}
		return keys;
	}

	function _escapeForQuoted(str, quoteChar) {
		if(quoteChar == undefined) { quoteChar = '"'; }

		str = str.replace(/\\/g, "\\\\");
		str = str.replace(new RegExp(quoteChar, "g"), "\\"+quoteChar);
		return str;
	}
	var e4q = _escapeForQuoted;


	var EVAL_WINDOW = window;
	var SHOWED_SYMBOL_ERROR = false;
	var MEM_STR_SIZE = 0x800000;
	var DEFAULTS = {
		"MSIE": "10_x86",
		"Firefox": "25_x86"
	};
	
	function initMemStr() {
		mem_str_init = '' +
			'window.mem_str = "";' +
			'window.mem_str_size = ' + MEM_STR_SIZE + ';' +
			'(function() {' +
				'window.mem_str = "A";' +
				'while(window.mem_str.length < window.mem_str_size/2) {' +
					'window.mem_str += window.mem_str;' +
				'}' +
				'window.mem_str = "BNARLY_MEMORY_STRING" + window.mem_str;' +
				(bInfo.name == "MSIE" ?
					"window.mem_str = window.mem_str.substring(0, window.mem_str_size/2);" :
					'window.mem_str = ["",window.mem_str.substring(0, window.mem_str_size/2)].join("");'
				) +
			'})();'
		EVAL_WINDOW.eval(mem_str_init);
	}
	initMemStr();

	/*
	-----------------------------------------------------------
	SETUP FUNCTIONS
	-----------------------------------------------------------
	*/
	function init() {
		initSymbolCache();
	}

	/*
	Set the window that the debugger will be attached to.
	*/
	function setMainWindow(win) {
		EVAL_WINDOW = win;
		initMemStr();
	}

	var USE_SYMBOL_CACHE = true;
	var SYMBOL_CACHE = {};
	/*
	Set whether a symbol cache should be used
	*/
	function setUseSymbolCache(trueFalse) {
		USE_SYMBOL_CACHE = trueFalse;
	}

	/*
	Populate the symbol cache with vftable symbols from "popular" browser
	modules (eg mshtml!*vftable* and jscript9!*vftable*)
	*/
	function populateSymbolCache() {
		if(!USE_SYMBOL_CACHE) { return; }
		var popularSymbolModules = {
			"MSIE": {
				"default": ["mshtml", "jscript9"],
				"8_x86": ["mshtml", "jscript"]
			},
			"Firefox": {
				"default": ["xul"]
			}
		};
		var modChoices = popularSymbolModules[bInfo.name];
		var mods = modChoices[getBrowserVersion()];
		if(mods == undefined) {
			mods = modChoices["default"];
		}

		for(var i = 0; i < mods.length; i++) {
			var mod = mods[i];
			var output = evalRaw("x " + mod + "!*vftable*");
			_addSymbolsToCache(output);
		}
	}

	function _addSymbolsToCache(output) {
		var lines = output.split("\n");
		var regex = /([a-f0-9]+) (.*vftable').*/;
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var match = regex.exec(line);
			if(match == null) { break; }

			var addr = parseInt(match[1], 16);
			var symbol = match[2];
			SYMBOL_CACHE[addr] = symbol;
		}
	}
	/*
	-----------------------------------------------------------
	SETUP FUNCTIONS
	-----------------------------------------------------------
	*/
	
	/*
	Return the name/family of the browser. Eg: MSIE
	*/
	function getBrowserName() {
		return bInfo.name;
	}

	/*
	Return a string that represents the version of the browser. Eg: 10_x86
	*/
	function getBrowserVersion() {
		var majorVersion = bInfo.version.split(".")[0];
		var type = bInfo.type;
		var version = majorVersion + "_" + type;
		return version;
	}

	/*
	Return the symbol server locations that should be in `.sympath` in order for
	bNarly to work correctly.
	*/
	function getSymbolServerLocations() {
		var locations = {
			"MSIE": ["http://msdl.microsoft.com/download/symbols"],
			"Firefox": ["http://symbols.mozilla.org/firefox"],
			"Chrome": ["http://chromium-browser-symsrv.commondatastorage.googleapis.com","http://msdl.microsoft.com/download/symbols"],
		};
		
		var loc = locations[bInfo.name];
		if(!loc) { loc = null; }
		return loc;
	};

	function isConnected() {
		var output = evalRaw(".echo connection test");
		return output.trim() == "connection test";
	}

	// ----------------------- Alloc Track
	
	function getAllocTrackBreakpoint() {
		var handlers = {
			"MSIE": _getMSIEAllocTrackBreakpoint,
			"Firefox": _getFirefoxAllocTrackBreakpoint
		};

		if(!handlers[bInfo.name]) {
			return null;
		}

		return handlers[bInfo.name](bInfo);
	}

	function _getMSIEAllocTrackBreakpoint(info) {
		var key = getBrowserVersion();

		var breakpoints = {
			"10_x86": {
				addr: 'ntdll!RtlAllocateHeap+e6',
				commands: [
					'.if(eax != 0) {',
						'.printf "ALLOC heap: %08x, size: %08x, addr: %08x\\n", poi(esp+4), poi(esp+c), eax ;',
					'} ;',
					'g'
				].join(" ")
			}
		};

		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["MSIE"]]; }
		return breakpoint;
	}

	function _getFirefoxAllocTrackBreakpoint(info) {
		var key = getBrowserVersion();

		var breakpoints = {
			"25_x86": {
				addr: 'mozglue!je_malloc+0x41',
				commands: [
					'.if(eax != 0) {',
						'.printf "ALLOC size: %08x, addr: %08x\\n", poi(esp+4), eax',
					'} ;',
					'g'
				].join(" ")
			}
		};

		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["Firefox"]]; }
		return breakpoint;
	}
	
	// ----------------------- Free Track
	
	function getFreeTrackBreakpoint() {
		var handlers = {
			"MSIE": _getMSIEFreeTrackBreakpoint,
			"Firefox": _getFirefoxFreeTrackBreakpoint
		};

		if(!handlers[bInfo.name]) {
			return null;
		}

		return handlers[bInfo.name](bInfo);
	}

	function _getMSIEFreeTrackBreakpoint(info) {
		var key = getBrowserVersion();

		var breakpoints = {
			"10_x86": {
				addr: 'ntdll!RtlFreeHeap',
				commands: [
					'.if($vvalid(poi(esp+c),1)) {',
						'.printf "FREE heap: %08x, addr: %08x, firstPtr: %08x\\n", poi(esp+4), poi(esp+c), poi(poi(esp+c))',
					'} .else {',
						'.printf "FREE heap: %08x, addr: %08x\\n", poi(esp+4), poi(esp+c)',
					'} ;',
					'g'
				].join(" ")
			}
		};

		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["MSIE"]]; }
		return breakpoint;
	}

	function _getFirefoxFreeTrackBreakpoint(info) {
		var key = getBrowserVersion();

		var breakpoints = {
			"25_x86": {
				addr: 'mozglue!je_free',
				commands: [
					'.if(poi(esp+4) != 0) {',
						'.if($vvalid(poi(esp+4),1)) {',
							'.printf "FREE addr: %08x, firstPtr: %08x\\n", poi(esp+4), poi(poi(esp+4))',
						'} .else {',
							'.printf "FREE addr: %08x\\n", poi(esp+4)',
						'}',
					'} ;',
					'g'
				].join(" ")
			}
		};

		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["Firefox"]]; }
		return breakpoint;
	}
	
	// ----------------------- Main Windbg Breakpoint

	/*
	Return the breakpoint for the current browser. If a breakpoint for the current
	version has not been explicitly defined, return the default breakpoint for
	the browser family.
	*/
	function getWindbgBreakpoint() {
		var handlers = {
			"Chrome": _getChromeWindbgBreakpoint,
			"MSIE": _getMSIEWindbgBreakpoint,
			"Firefox": _getFirefoxWindbgBreakpoint
		};
		
		if(!handlers[bInfo.name]) {
			return null;
		}
		
		return handlers[bInfo.name](bInfo);
	};
	
	function _getChromeWindbgBreakpoint(info) {
		return null;
	};

	function _getMSIEWindbgBreakpoint(info) {
		var key = getBrowserVersion();
		
		/*
		-First argument to Math.min must be 111111, else breakpoint merely continues
		-Second argument to Math.min is the command to execute
		-Third argument to Math.min is the (optional) out string
		
		@$t0 will be set to the fourth argument, if a fourth argument exists
		*/
		var breakpoints = {
			"11_x86": ['bu jscript9!Js::Math::Min "',
				// evaluate windbg commands
				'.if(poi(esp+10) == 0n222223) {',
					// if a fourth argument was passed in, save its pointer in @$t0
					'.if((poi(esp+8) & 0xff) > 4) {',
						'r @$t0 = poi(esp+1c)',
					'} ;',

					// write windbg commands found in second parameter to cmd_to_exec.txt
					'.writemem cmd_to_exec.txt poi(poi(esp+14)+c) L?(poi(poi(esp+14)+8)*2) ;',

					// execute windbg commands
					'$$><cmd_to_exec.txt ;',

					// read the output from executed commands back into the third argument (a string)
					'.if((poi(esp+8) & 0xff) > 3) {',
						'.readmem output.txt poi(poi(esp+18)+c) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
						'g',
					'}',

				// simple logging
				'} .elsif(poi(esp+10) == 0n444445) {',
					'.printf \\"%mu\\\\n\\", poi(poi(esp+14)+c) ;',
					'g',
				'} .else {',
					'g',
				'}',
			'"'].join(" "),

			"10_x86": ['bu jscript9!Js::Math::Min "',
				// evaluate windbg commands
				'.if(poi(esp+10) == 0n222223) {',
					// if a fourth argument was passed in, save its pointer in @$t0
					'.if((poi(esp+8) & 0xff) > 4) {',
						'r @$t0 = poi(esp+1c)',
					'} ;',

					// write windbg commands found in second parameter to cmd_to_exec.txt
					'.writemem cmd_to_exec.txt poi(poi(esp+14)+c) L?(poi(poi(esp+14)+8)*2) ;',

					// execute windbg commands
					'$$><cmd_to_exec.txt ;',

					// read the output from executed commands back into the third argument (a string)
					'.if((poi(esp+8) & 0xff) > 3) {',
						'.readmem output.txt poi(poi(esp+18)+c) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
						'g',
					'}',

				// simple logging
				'} .elsif(poi(esp+10) == 0n444445) {',
					'.printf \\"%mu\\\\n\\", poi(poi(esp+14)+c) ;',
					'g',
				'} .else {',
					'g',
				'}',
			'"'].join(" "),
			
			// this will happen with TabProcGrowth=0 on x64 systems
			// "10_x64": TODO
			
			"9_x86": ['bu jscript9!Js::Math::Min "',
				// evaluate windbg commands
				'.if(poi(esp+10) == 0n222223) {',
					// if a fourth argument was passed in, save its pointer in @$t0
					'.if((poi(esp+8) & 0xff) > 4) {',
						'r @$t0 = poi(esp+1c)', // TODO
					'} ;',

					// write windbg commands found in second parameter to cmd_to_exec.txt
					'.writemem cmd_to_exec.txt poi(poi(esp+14)+c) L?(poi(poi(esp+14)+8)*2) ;',

					// execute windbg commands
					'$$><cmd_to_exec.txt ;',

					// read the output from executed commands back into the third argument (a string)
					'.if((poi(esp+8) & 0xff) > 3) {',
						'.readmem output.txt poi(poi(esp+18)+c) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
						'g',
					'}',

				// simple logging
				'} .elsif(poi(esp+10) == 0n444445) {',
					'.printf \\"%mu\\\\n\\", poi(poi(esp+14)+c) ;',
					'g',
				'} .else {',
					'g',
				'}',
			'"'].join(" "),

			// this will happen with TabProcGrowth=0 on x64 systems
			//"9_x64": TODO

			"8_x86": ['r @$t7 = 0 ;', 'bu jscript!JsMin "',
				// args are pushed from right to left
				// poi(esp+10) == argcount
				// poi(esp+14) == args array. Each item in array is size 0x10, with val at +8
				// last element in array (first argument to Math.min) is:
				
				// ARG ARRAY BASE
				'r @$t1 = poi(esp+14)+8 ;',
				// arg count
				'r @$t2 = poi(esp+10) & 0xff ;',
				// first arg
				'r @$t3 = poi(@$t1+((@$t2-1)*10)) ;',

				// stupid hack to get a reference to the mem_str before it gets wiped
				// off the stack
				'.if(@$t7 == 0) {',
					'r @$t7 = poi(esp-0x22a4)',
				'} ;',

				'.if(@$t2 < 2) {',
					'g',
				'} .else {',
					// evaluate windbg commands
					'.if(@$t3 == 0n111111) {',
						// if a fourth argument was passed in, save its pointer in @$t0
						'.if(@$t2 > 3) {',
							'r @$t0 = poi(poi(@$t1+((@$t2-4)*10))+8)',
						'} ;',

						// write windbg commands found in second parameter to cmd_to_exec.txt
						'.writemem cmd_to_exec.txt poi(poi(@$t1+((@$t2-2)*10))+8) L?poi(poi(poi(@$t1+((@$t2-2)*10))+8)-4) ;',

						// execute windbg commands
						'$$><cmd_to_exec.txt ;',

						// read the output from executed commands back into the third argument (a string)
						'.if(@$t2 > 2) {',
							// not sure of the specifics on this, but I think this string is just a copy
							// and not the original string.
							//'.readmem output.txt poi(poi(@$t1+((@$t2-3)*10))+8) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
							//
							// the only other BNARLY_MEMORY_STRING can be found at poi(esp-0x22a4) 
							// UNTIL IT GETS WIPED OFF THE STACK!
							//'.readmem output.txt poi(esp-0x22a4) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
							//
							// use @$t7 instead :^)
							'.readmem output.txt @$t7 L?' + toWAddr(MEM_STR_SIZE) + ' ;',
							'g',
						'}',

					// simple logging
					'} .elsif(@$t3 == 0n222222) {',
						'.printf \\"%mu\\\\n\\", poi(poi(@$t1+((@$t2-2)*10))+8) ;',
						'g',
					'} .else {',
						'g',
					'}',
				'}',
			'"'].join(" "),

			//"8_x64": TODO
		};
		
		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["MSIE"]]; }
		return breakpoint;
	};
	
	function _getFirefoxWindbgBreakpoint(v) {
		var key = getBrowserVersion();

		var breakpoints = {
			"25_x86": ['bu mozjs!js_math_min "',
				// evaluate windbg commands
				'.if(poi(poi(esp+c)+10) == 0n111111) {',
					// if a fourth argument was passed in, save its pointer in @$t0
					'.if((poi(esp+8) & 0xff) > 3) {',
						'r @$t0 = poi(poi(esp+c)+28)',
					'} ;',

					// write windbg commands found in second parameter to cmd_to_exec.txt
					'.writemem cmd_to_exec.txt poi(poi(poi(esp+c)+18)+4) L?((poi(poi(poi(esp+c)+18))>>4)*2) ;',

					// execute windbg commands
					'$$><cmd_to_exec.txt ;',

					// read the output from executed commands back into the third argument (a string)
					'.if((poi(esp+8) & 0xff) > 2) {',
						'.readmem output.txt poi(poi(poi(esp+c)+20)+4) L?' + toWAddr(MEM_STR_SIZE) + ' ;',
						'g',
					'}',

				// simple logging
				'} .elsif(poi(poi(esp+c)+10) == 0n222222) {',
					'.printf \\"%mu\\\\n\\", poi(poi(poi(esp+c)+18)+4) ;',
					'g',
				'} .else {',
					'g',
				'}',
			'"'].join(" ")
		}
		var breakpoint = breakpoints[key];
		if(!breakpoint) { breakpoint = breakpoints[DEFAULTS["Firefox"]]; }
		return breakpoint;
	};
	
	/*
	-----------------------------------------------------------
	UTILITY FUNCTIONS
	-----------------------------------------------------------
	*/
	
	/*
	Force execution to pause
	*/
	function int3() {
		run(".echo INT3");
	}
	
	/*
	Print the message and continue. This method should be safe for ANY message content
	without needing to escape anything.
	*/
	function log(msg) {
		msg = msg.substr(0, msg.length);
		EVAL_WINDOW.Math.min(222222, msg);
	};

	/*
	-----------------------------------------------------------
	CANDY FUNCTIONS
	-----------------------------------------------------------
	*/

	/*
	Evaluate the given expression and return the result. The result will *always*
	be a number. This is the same as running the windbg command:

	`? <expression>`
	*/
	function evalExpr(expression) {
		var res = evalRaw("? " + expression);
		return _getEvalExprInt(res);
	};
	
	function _getEvalExprInt(output) {
		var regex = /Evaluate expression: ([0-9]+) = ([a-f0-9]+)/g;
		var match = regex.exec(output);
		return parseInt(match[1]);
	};
	
	/*
	Run the `cmd` without waiting for the created process to exit
	*/
	function shell(cmd) {
		run('.block { .shell -ci ".echo blah" start ' + cmd + '} ; g');
	};

	var heapAllocBpId = null;
	var heapFreeBpId = null;
	/*
	Begin tracking heap allocs/frees. Retrieve tracked heap events by calling
	`stopHeapTracking()`
	*/
	function startHeapTracking() {
		var allocBp = getAllocTrackBreakpoint();
		var freeBp = getFreeTrackBreakpoint();

		heapFreeBpId = setBreakpoint(freeBp.addr, freeBp.commands);
		heapAllocBpId = setBreakpoint(allocBp.addr, allocBp.commands);
		run(".logopen /u output.txt", "g");
	}

	function _parseHeapTrackingEvent(output) {
		/*
		ALLOC heap: 00680000, size: 00001000, addr: 00000000
		FREE heap: 00680000, addr: 04a27470
		*/

		var heapTypeRegex = /(FREE|ALLOC) (.*)/;
		var match = heapTypeRegex.exec(output);
		if(match == null) { return null; }

		eventInfo = {
			type: match[1]
		};

		var itemRegex = /([\w]+): ([a-f0-9]+)/;
		var items = match[2].split(",");
		for(var i = 0; i < items.length; i++) {
			var item = items[i];
			var match = itemRegex.exec(item);
			if(match == null) { break; }

			eventInfo[match[1]] = parseInt(match[2], 16);
		}

		return eventInfo;
	}

	function _processHeapEvents(output, timeline, unAllocatedFrees, unFreedAllocs) {
		var lines = output.split("\n");
		
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var info = _parseHeapTrackingEvent(line);
			if(info == null) { break; }

			info.symbol = "";
			if(info.firstPtr) {
				info.symbol = info.firstPtr;
			} else {
				info.firstPtr = null;
			}

			if(info.type == "FREE") {
				if(unFreedAllocs[info.addr]) {
					delete unFreedAllocs[info.addr];
				} else {
					unAllocatedFrees[info.addr] = info;
				}
			} else if(info.type == "ALLOC") {
				unFreedAllocs[info.addr] = info;
			} else {
				continue;
			}

			timeline.push(info);
		}
	}

	function _resolveFreeEventSymbols(timeline) {
		var freedSymbolsToFetch = [];
		var freeEvents = [];
		for(var i = 0; i < timeline.length; i++) {
			var heapEvent = timeline[i];
			if(heapEvent.type != "FREE") { continue; }
			if(heapEvent.firstPtr == null) { continue; }

			freedSymbolsToFetch.push(heapEvent.firstPtr);
			freeEvents.push(heapEvent);
		}
		var freedSymbolsResults = getSymbols(freedSymbolsToFetch);
		for(var i = 0; i < freeEvents.length; i++) {
			var freeEvent = freeEvents[i];
			var symbol = freedSymbolsResults[freeEvent.firstPtr];
			if(symbol == "" && freeEvent.firstPtr != null) {
				symbol = freeEvent.firstPtr;
			}
			freeEvent.symbol = symbol;
		}
	}

	function _resolveAllocEventSymbols(unFreedAllocs) {
		var allocationDpps = [];
		var allocationEvents = [];
		for(var addr in unFreedAllocs) {
			addr = parseInt(addr);
			var allocEvent = unFreedAllocs[addr];
			allocationEvents.push(allocEvent);
			allocationDpps.push("dpp " + toWAddr(addr) + " L?1");
		}
		var dppResults = evalRaws.apply(this, allocationDpps);
		var toFetchSymbols = [];
		var toFetchSymbolsEvents = [];
		var regex = /([a-f0-9]+)\s+([^\s].*)/;
		for(var i = 0; i < allocationEvents.length; i++) {
			var allocEvent = allocationEvents[i];
			var match = regex.exec(dppResults[i].trim());
			allocEvent.symbol = (match ? match[2] : "");
			if(allocEvent.symbol != "????????") {
				// 00701820  67c66638 6838e622 MSHTML!CSecurityContext::QueryInterface
				var pointerMatch = regex.exec(allocEvent.symbol);
				if(pointerMatch) {
					allocEvent.firstPtr = parseInt(pointerMatch[1], 16);
					toFetchSymbols.push(allocEvent.firstPtr);
					toFetchSymbolsEvents.push(allocEvent);
				}
			}
		}
		var symbolResults = getSymbols(toFetchSymbols);
		for(var i = 0; i < toFetchSymbols.length; i++) {
			var allocEvent = toFetchSymbolsEvents[i];
			var symbolResult = symbolResults[allocEvent.firstPtr];
			if(symbolResult != "") {
				allocEvent.symbol = symbolResult;
			}
		}
	}

	/*
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
	*/
	function stopHeapTracking() {
		clearBreakpoint(heapAllocBpId);
		clearBreakpoint(heapFreeBpId);
		var output = _doCommand([".logclose"], true, undefined, undefined, true);
		
		var timeline = [];
		var unAllocatedFrees = {};
		var unFreedAllocs = {};

		_processHeapEvents(output, timeline, unAllocatedFrees, unFreedAllocs);
		_resolveFreeEventSymbols(timeline);
		_resolveAllocEventSymbols(unFreedAllocs);

		return {
			timeline: timeline,
			unAllocatedFrees: unAllocatedFrees,
			unFreedAllocs: unFreedAllocs
		};
	}
	
	var arrayObjectInstanceVftablePtr = null;
	/*
	Return a pointer to the given object. If `isOnlyName` is true, the obj is assumed to be a string
	and will be evaluated in the window that `setMainWindow` was set to.
	*/
	function getObjectPtr(obj, isOnlyObjName) {
		res = _doCommand(['? @$t0'], true, obj, isOnlyObjName);
		var ptrVal = _getEvalExprInt(res);

		if(bInfo.name == "MSIE") {
			var wrapperType = {
				"default": {
					symbol: "jscript9!Projection::ArrayObjectInstance::`vftable'",
					offset: 0x18
				},
				"9_x86": {
					symbol: "jscript9!Js::CustomExternalObject::`vftable'",
					offset: 0x14
				},
				"8_x86": {
					symbol: "mshtml!s_apfnTrackerTearoffVtable",
					offset: 0xc
				}
			}

			var symbolInfo = wrapperType[getBrowserVersion()];
			if(symbolInfo == undefined) {
				symbolInfo = wrapperType["default"];
			}

			if(!arrayObjectInstanceVftablePtr) {
				arrayObjectInstanceVftablePtr = evalExpr(symbolInfo.symbol);
			}

			var firstPoi = poi(ptrVal);
			if(poi(ptrVal) == arrayObjectInstanceVftablePtr) {
				// might be different for different browser versions
				ptrVal = poi(ptrVal + symbolInfo.offset);
			}
		} else if(bInfo.name == "Firefox") {
			var firstPtrs = dpp(ptrVal, 5, true);
			if(firstPtrs[1].symbol.toLowerCase().indexOf("class") != -1 &&
					firstPtrs[4].symbol.indexOf("vftable") != -1) {
				ptrVal = firstPtrs[4].val;
			}
		}

		return ptrVal;
	};

	/*
	Return the size of the memory allocation referenced by ptr. An
	object is returned with at least the two members:

		`{base: <addr>, size: <size>}`

	More members might be added to the object, depending on which allocator
	is used.

	If the memory allocation size/base could not be determined, null
	is returned.
	*/
	function getObjectSize(ptr) {
		if(bInfo.name == "MSIE") {
			return _getObjectSizeMSIE(ptr);
		} else if(bInfo.name == "Firefox" ) {
			// TODO: create jemalloc windbg script!
			return null;
		}
		return null;
	}

	function _getObjectSizeMSIE(ptr, numTries) {
		if(numTries == undefined) { numTries = 0; }

		var output = evalRaw("!heap -p -a " + toWAddr(ptr));

		/*
		I encounter this on x64 windbg when trying to use !heap -p -a:

		*************************************************************************
		***                                                                   ***
		***                                                                   ***
		***    Your debugger is not using the correct symbols                 ***
		***                                                                   ***
		***    In order for this command to work properly, your symbol path   ***
		***    must point to .pdb files that have full type information.      ***
		***                                                                   ***
		***    Certain .pdb files (such as the public OS symbols) do not      ***
		***    contain the required information.  Contact the group that      ***
		***    provided you with these symbols if you need this command to    ***
		***    work.                                                          ***
		***                                                                   ***
		***    Type referenced: wow64!_TEB32                                  ***
		***                                                                   ***
		*************************************************************************

		I am not aware of any ways to resolve this besides using x86 windbg
		instead of x64
		*/
		if(output.indexOf("Your debugger is not using the correct symbols") != -1) {
			if(!SHOWED_SYMBOL_ERROR) {
				if(numTries == 0) {
					var regex = /.*Type referenced:\s*([^\s]+)\s*\*\*\*/;
					var match = regex.exec(output);
					var missingSymbol = match[1];
					if(missingSymbol == "ntdll!_PEB") {
						run(".reload /f ntdll.dll", "g");
						return _getObjectSizeMSIE(ptr, numTries+1);
					}
				} else {
					alert([
						"Somehow some symbols are missing for !heap -p -a <addr> to work!",
						"This might not be fixable",
						"Missing symbol: " + missingSymbol,
						"For allocation size snapping to work, use x86 windbg"
					].join("\n\n"));
					SHOWED_SYMBOL_ERROR = true;
				}
			}
			return null;
		}

		var lines = output.split("\n");
		if(lines.length < 3) {
			return null;
		}

		/*
		eg:       
		0:006> !heap -p -a 0n3376352
		    address 003384e0 found in
		    _HEAP @ 280000
		      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
		        003384d8 0008 0000  [00]   003384e0    00034 - (busy)
		          MSHTML!CDivElement::`vftable'
		*/			
		var regex = /^\s*_HEAP @ ([0-9a-f]+).*/
		var match = regex.exec(lines[1]);
		var heap = parseInt(match[1], 16);

		//               heap entry    size          prev          flags      user ptr      user size
		var regex = /^\s*([0-9a-f]+)\s*([0-9a-f]+)\s*([0-9a-f]+)\s*(\[..\])\s*([0-9a-f]+)\s*([0-9a-f]+).*/
		var match = regex.exec(lines[3]);
		var heapEntry = parseInt(match[1], 16);
		var heapSize = parseInt(match[2], 16);
		var userPtr = parseInt(match[5], 16);
		var userSize = parseInt(match[6], 16);

		res = {
			base: userPtr,
			size: userSize,
			heap: heap,
			heapEntry: heapEntry,
			heapSize: heapSize
		}

		return res;
	}
	
	/*
	-----------------------------------------------------------
	SYMBOL RESOLUTION FUNCTIONS
	-----------------------------------------------------------
	*/

	function _symbolHelper(addr, output) {
		output = output.trim();
		var lines = output.split("\n");

		/*
		0:008> ln 761c2c51
		(761c2c51)   kernel32!WinExec   |  (761c2d67)   kernel32!FatalExit
		Exact matches:
		    kernel32!WinExec = <no type information
		*/
		if(lines.length > 1) {
			var line = lines[0];
			var matches = line.split("|");
			var regex = /^\s*\(([0-9a-f]+)\)\s*([^\s].*)/
			for(var i = 0; i < matches.length; i++) {
				var part = matches[i];
				var match = regex.exec(part);
				if(!match) { continue; }
				var partAddr = parseInt(match[1], 16);
				var symbol = match[2].trim();
				if(partAddr == addr) {
					return symbol;
				}
			}
		}
		return "";
	}

	/*
	Return the symbol at the provided address. Returns "" if no
	matching symbol is found.
	*/
	function getSymbol(addr) {
		if(SYMBOL_CACHE[addr]) { return SYMBOL_CACHE[addr]; }

		var output = evalRaw("ln " + toWAddr(addr));
		var symbol = _symbolHelper(addr, output);
		SYMBOL_CACHE[addr] = symbol;
	}

	/*
	Return the symbols for each address in addrs in an object of the form
	{addr: symbol, ...}. If no matching symbol is found, the symbol value
	will be "".
	*/
	function getSymbols(addrs) {
		var res = {};
		// set > list (keys of object vs array)
		var noCachedSymbols = {};
		for(var i = 0; i < addrs.length; i++) {
			var addr = addrs[i];
			var symbol = SYMBOL_CACHE[addr];
			if(symbol == undefined) {
				noCachedSymbols[addr] = null;
			} else {
				res[addr] = symbol;
			}
		}

		var commands = [];
		var toLookupStrings = getKeys(noCachedSymbols);
		var toLookup = [];
		for(var i = 0; i < toLookupStrings.length; i++) {
			var addr = parseInt(toLookupStrings[i]);
			toLookup.push(addr);
			commands.push("ln " + toWAddr(addr));
		}
		var records = evalRaws.apply(this, commands);
		
		for(var i = 0; i < records.length; i++) {
			var record = records[i];
			var symbol = _symbolHelper(toLookup[i], record);
			res[toLookup[i]] = symbol;
			SYMBOL_CACHE[toLookup[i]] = symbol;
		}
		return res;
	}
	
	/*
	-----------------------------------------------------------
	SYMBOL RESOLUTION FUNCTIONS
	-----------------------------------------------------------
	*/

	/*
	Sets a breakpoint at `addr` (may also be a symbol). Default breakpoint
	`type` is `bp`, may also pass in `bu` or `bm`.

	The `commands` argument is an unescaped string of commands. The commands
	will automatically be escaped.

	Returns the breakpoint id that can be passed to `clearBreakpoint(bpId)` to
	remove the breakpoint.
	*/
	function setBreakpoint(addr, commands, type) {
		if(type == undefined) { type = "bp"; }

		var escapeCommands = e4q(commands, '"');
		if(escapeCommands.trim() != "") {
			escapeCommands = '"' + escapeCommands + '"';
		}
		var outputs = evalRaws([type + " " + addr], [type + " " + addr + " " + escapeCommands + " "]);
		var redefinedBpOutput = outputs[1];
		var regex = /.*breakpoint (\d+) redefined.*/;
		var match = regex.exec(redefinedBpOutput);
		var bpId = parseInt(match[1]);
		return bpId;
	}

	/*
	Clear the breakpoint associated with `bpId`
	*/
	function clearBreakpoint(bpId) {
		run("bc " + bpId, "g");
	}

	/*
	-----------------------------------------------------------
	MEMORY ACCESS FUNCTIONS
	-----------------------------------------------------------
	*/
	
	function _ddHelper(output) {
		var res = [];
		var lines = output.split("\n");
		var regex = /\s*([0-9a-f]+)\s*([0-9a-f]+)\s*([^\s].*)?/;
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var match = regex.exec(line);
			if(!match) { continue; }
			res.push({
				addr: parseInt(match[1], 16),
				val: parseInt(match[2], 16),
				symbol: match[3] ? match[3].trim() : ""
			});
		}
		return res;
	}

	function _dStringHelper(command, address, brokenUp, limit) {
		// TODO: is this necessary????
		// if(limit == undefined) { limit = 0x1000; }
		//var output = evalRaw(command + " /c 0x10 0n" + address + " L?0n" + limit);

		var output = evalRaw(command + " /c 0x10 " + toWAddr(address));
		var res = [];
		var lines = output.split("\n");
		var regex = /^\s*([0-9a-f]+)\s*"(.*)"/
		var total = "";
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var match = regex.exec(line);
			var lineAddr = parseInt(match[1], 16);
			var lineVal = match[2];
			res.push({addr:lineAddr, val:lineVal});
			total += lineVal;
		}
		if(brokenUp) {
			return res;
		} else {
			return total;
		}
	}

	/*
	Return the string referenced by `address`.

	If `brokenUp` is true, an array of objects of the form `{addr:<address>, val:<val>}` will
	be returned.

	`limit` limits the length of the string. Eg: `da <addr> L?0n<limit>`
	*/
	function da(address, brokenUp, limit) {
		if(brokenUp == undefined) { brokenUp = false; }
		return _dStringHelper("da", address, brokenUp, limit);
	}

	/*
	Return the unicode string referenced by `address`.

	If `brokenUp` is true, an array of objects of the form `{addr:<address>, val:<val>}` will
	be returned.

	`limit` limits the length of the unicode string. Eg: `du <addr> L?0n<limit>`
	*/
	function du(address, brokenUp, limit) {
		if(brokenUp == undefined) { brokenUp = false; }
		return _dStringHelper("du", address, brokenUp, limit);
	}

	function _dStarHelper(command, address, num, symLookup) {
		var output = evalRaw(command + " /c 1 " + toWAddr(address) + " L?0n" + num);
		var res = _ddHelper(output);
		if(symLookup) {
			var addrs = [];
			for(var i = 0; i < res.length; i++) {
				var info = res[i];
				addrs.push(info.val);
			}
			var symbols = getSymbols(addrs);
			for(var i = 0; i < res.length; i++) {
				var info = res[i];
				var symbol = symbols[info.val];

				// only overwrite the symbol obtained from _ddHelper if we got
				// a different symbol from the individual lookup (use case:
				// using ddp/ddp and vftables)
				if(symbol != "" && symbol != undefined) {
					info.symbol = symbol;
				}
			}
		}
		return res;
	}

	/*
	Return an array of objects containing the dword values and symbols at
	each address:

	`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`

	If `symLookup` is true, an attempt will be made to resolve symbols.
	*/
	function dd(address, num, symLookup) {
		return _dStarHelper("dd", address, num, symLookup);
	}

	/*
	Return an array of objects containing the pointer-sized values and
	symbols at each address:

	[{addr: <val>, val: <val>, symbol: <val>}, ... ]

	If `symLookup` is true, an attempt will be made to resolve symbols.
	*/
	function dp(address, num, symLookup) {
		return _dStarHelper("dp", address, num, symLookup);
	}

	/*
	Return an array of objects containing the dword-sized values and
	symbols at each	address:

	`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`

	If `symLookup` is true, an attempt will be made to resolve symbols. The
	windbg command `ddp` by default will display the dereferenced pointer and
	the memory at the resulting location. Any results from `symLookup` will
	override the symbols from the windbg output of `ddp`.
	*/
	function ddp(address, num, symLookup) {
		return _dStarHelper("ddp", address, num, symLookup);
	}

	/*
	Return an array of objects containing the pointer-sized values and
	symbols at each	address:

	`[{addr: <val>, val: <val>, symbol: <val>}, ... ]`


	If `symLookup` is true, an attempt will be made to resolve symbols. The
	windbg command `dpp` by default will display the dereferenced pointer and
	the memory at the resulting location. Any results from `symLookup` will
	override the symbols from the windbg output of `dpp`.
	*/
	function dpp(address, num, symLookup) {
		return _dStarHelper("dpp", address, num, symLookup);
	}

	/*
	Return the byte at the given address
	*/
	function by(address) {
		return evalExpr("by(" + toWAddr(address) + ")");
	}
	
	/*
	Return the word at the given address
	*/
	function wo(address) {
		return evalExpr("wo(" + toWAddr(address) + ")");
	}
	
	/*
	Return the dword at the given address
	*/
	function dwo(address) {
		return evalExpr("dwo(" + toWAddr(address) + ")");
	}
	
	/*
	Return the qword at the given address
	*/
	function qwo(address) {
		return evalExpr("qwo(" + toWAddr(address) + ")");
	}
	
	/*
	Return the pointer at the given address
	*/
	function poi(address) {
		return evalExpr("poi(" + toWAddr(address) + ")");
	}
	

	function _memDumpHelper(type, address, num) {
		var output = evalRaw(type + " /c 1 " + toWAddr(address) + " L?0n" + num);
		var lines = output.split("\n");

		// only db will have a match in the third group, and it will only
		// be one character
		var regex = /([a-f0-9]+)\s+([a-f0-9`]+)(\s+(.))?/;
		var res = [];
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			var match = regex.exec(line);
			if(match == null) { continue; }

			res.push({
				addr: toInt(match[1]),
				val: toInt(match[2]),
				rep: match[4]
			})
		}

		return res;
	}

	/*
	Return an array of objects representing `num` bytes starting at `address`.

	Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`
	*/
	function bytes(address, num) {
		return _memDumpHelper("db", address, num);
	};
	
	/*
	Return an array of objects representing `num` words starting at `address`.

	Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`
	*/
	function words(address, num) {
		return _memDumpHelper("dw", address, num);
	}
	
	/*
	Return an array of objects representing `num` dwords starting at `address`.

	Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`
	*/
	function dwords(address, num) {
		return _memDumpHelper("dd", address, num);
	}
	
	/*
	Return an array of objects representing `num` qwords starting at `address`.

	Objects are of the form `{addr: <addr>, val: <val>, rep: <rep>}`
	*/
	function qwords(address, num) {
		return _memDumpHelper("dq", address, num);
	}

	/*
	-----------------------------------------------------------
	MEMORY WRITE FUNCTIONS
	-----------------------------------------------------------
	*/

	function _memEditHelper(type, address, values) {
		var convertedValues = [];
		for(var i =0 ; i < values.length; i++) {
			convertedValues.push(toWAddr(values[i]));
		}
		evalRaw(type + " " + toWAddr(address) + " " + convertedValues.join(" "));
	}

	function _memEditArgsValidator(args) {
		if(args.length < 2) {
			throw "Memory editing functions (eb, ew, ed, eq) require at least two parameters: (<addr>, <value>, ...)"
		}
	}

	/*
	Overwrite bytes at `addr` with values `val1`, `val2`, ...
	*/
	function eb(/*addr, val1, val2, ...*/) {
		arguments = argsToArray(arguments);
		_memEditArgsValidator(arguments);
		_memEditHelper("eb", arguments[0], arguments.slice(1));
	}

	/*
	Overwrite words at `addr` with values `val1`, `val2`, ...
	*/
	function ew(/*addr, val1, val2, ...*/) {
		arguments = argsToArray(arguments);
		_memEditArgsValidator(arguments);
		_memEditHelper("ew", arguments[0], arguments.slice(1));
	}

	/*
	Overwrite dwords at `addr` with values `val1`, `val2`, ...
	*/
	function ed(/*addr, val1, val2, ...*/) {
		arguments = argsToArray(arguments);
		_memEditArgsValidator(arguments);
		_memEditHelper("ed", arguments[0], arguments.slice(1));
	}

	/*
	Overwrite qwords at `addr` with values `val1`, `val2`, ...
	*/
	function eq(/*addr, val1, val2, ...*/) {
		arguments = argsToArray(arguments);
		_memEditArgsValidator(arguments);
		_memEditHelper("eq", arguments[0], arguments.slice(1));
	}

	/*
	-----------------------------------------------------------
	CORE FUNCTIONS
	-----------------------------------------------------------
	*/
	
	/*
	Run the given command. Do not return the output. Code execution must be
	explicitly resumed with `g`.
	*/
	function run(/*cmd1, cmd2, ...*/) {
		_doCommand(arguments);
	};
	
	/*
	Run the given commands found in arguments and return the output. Code
	execution will automatically be resumed.
	*/
	function evalRaw(/*cmd1, cmd2, ...*/) {
		return _doCommand(arguments, true);
	};

	/*
	Run each of the command groups in arguments and return an
	array containing the output for each command.

	Eg:
		evalRaws("bl", "bp some!function", "bl")

	The above call to evalRaws could be used as an inefficient way to
	determine the id of a new breakpoint.
	*/
	function evalRaws() {
		var commands = Array.prototype.slice.call(arguments, 0);

		var totalCommands = [];
		var commandSepString = "--==--==--"
		for(var i = 0; i < commands.length; i++) {
			totalCommands = totalCommands.concat(commands[i]);
			if(i < commands.length-1) {
				totalCommands.push(".echo " + commandSepString);
			}
		}
		var output = _doCommand(totalCommands, true);
		var results = output.split(commandSepString);
		return results;
	}
	
	function _doCommand(commands, return_output, fourth_arg, isOnlyObjName, noLogOpen) {
		// make sure commands is an array and not an Arguments object
		commands = argsToArray(commands);

		if(return_output && !noLogOpen) {
			commands.unshift(".logopen /u output.txt");
			for(var i = 0; i < 0x100; i++) {
				commands.push(".echo IGNORE ME");
			}
			commands.push(".logclose");
		}
		
		if(commands.length == 0) { return; }
		
		commands = commands.join("\n");
		commands = _convertToAscii(commands);
		commands = commands.substr(0, commands.length);
		
		window.commands = commands;
		window.fourth_arg = fourth_arg;

		var to_eval = "var w = window" + (EVAL_WINDOW == window ? "" : ".opener") + "; ";
		if(return_output) {
			if(fourth_arg) {
				if(isOnlyObjName) {
					to_eval += 'Math.min(111111, w.commands, window.mem_str, ' + fourth_arg + ')';
				} else {
					to_eval += 'Math.min(111111, w.commands, window.mem_str, w.fourth_arg)';
				}
			} else {
				to_eval += 'Math.min(111111, w.commands, window.mem_str);';
			}
			EVAL_WINDOW.eval(to_eval);
			return _filterJunkFromMemStr(EVAL_WINDOW.mem_str);
		} else {
			to_eval += 'Math.min(111111, w.commands);';
			EVAL_WINDOW.eval(to_eval);
		}
	};
	
	function hex(num, padTo) {
		return _hex(num, padTo);
	};

	function _hex(num, padTo) {
		var res = num.toString(16);
		while(res.length < padTo) {
			res = "0" + res;
		}
		return res;
	};

	function _convertToAscii(str) {
		var encodeWord = function(w) {
			return "\\u" + _hex(w[1], 2) + _hex(w[0], 2);
		};
	
		var res = "";
		var currWord = [];
		for(var i = 0; i < str.length; i++) {
			if(currWord.length > 1) {
				res += encodeWord(currWord);
				currWord = [];
			}
			currWord.push(str.charCodeAt(i));
		}
		if(currWord.length == 1) { currWord.push(20); }
		res += encodeWord(currWord);
		var realRes = eval('"' + res + '"');
		return realRes;
	};
	
	function _filterJunkFromMemStr(str) {
		var lines = str.split("\n");
		var resLines = [];
		for(var i = 0; i < lines.length; i++) {
			var line = lines[i];
			if(line.indexOf("Opened log file") != -1) {
				continue;
			}
			if(line.indexOf("IGNORE ME") != -1) {
				break;
			}
			if(line.indexOf("Closing open log file") != -1) {
				break;
			}
			resLines.push(line);
		}
		return resLines.join("\n");
	};

	return {
		/*
		----------------------------------------------
		BNARLY CONFIG FUNCTIONS
		----------------------------------------------
		*/
		setMainWindow: setMainWindow,
		setUseSymbolCache: setUseSymbolCache,
		populateSymbolCache: populateSymbolCache,

		/*
		----------------------------------------------
		UTILITY FUNCTIONS
		----------------------------------------------
		*/
		int3: int3,
		log: log,
	
		/*
		----------------------------------------------
		SETUP FUNCTIONS
		----------------------------------------------
		*/
		getWindbgBreakpoint: getWindbgBreakpoint,
		getSymbolServerLocations: getSymbolServerLocations,
		getBrowserVersion: getBrowserVersion,
		getBrowserName: getBrowserName,
		isConnected: isConnected,
		
		/*
		----------------------------------------------
		CANDY FUNCTIONS
		----------------------------------------------
		*/
		evalExpr: evalExpr,
		startHeapTracking: startHeapTracking,
		stopHeapTracking: stopHeapTracking,
		getObjectPtr: getObjectPtr,
		getObjectSize: getObjectSize,
		
		/*
		----------------------------------------------
		SYMBOL RESOLUTION FUNCTIONS
		----------------------------------------------
		*/
		getSymbol: getSymbol,
		getSymbols: getSymbols,

		/*
		----------------------------------------------
		BREAKPOINT FUNCTIONS
		----------------------------------------------
		*/
		setBreakpoint: setBreakpoint,
		clearBreakpoint: clearBreakpoint,

		/*
		----------------------------------------------
		MEMORY ACCESS FUNCTIONS
		----------------------------------------------
		*/

		// string functions
		da: da,
		du: du,

		// option to resolve symbols
		dd: dd,
		dp: dp,
		ddp: dpp,
		dpp: dpp,

		// single memory access
		by: by,
		wo: wo,
		dwo: dwo,
		qwo: qwo,
		poi: poi,

		// mass raw memory dump
		db: bytes,
		bytes: bytes,
		words: words,
		dwords: dwords,
		qwords: qwords,
		
		/*
		----------------------------------------------
		MEMORY WRITE FUNCTIONS
		----------------------------------------------
		*/
		eb: eb,
		ew: ew,
		ed: ed,
		eq: eq,

		/*
		----------------------------------------------
		CORE FUNCTIONS
		----------------------------------------------
		*/
		run: run,
		evalRaw: evalRaw,
		shell: shell,
	}
})();