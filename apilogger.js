'use strict';

r2frida.pluginRegister('apilog', function (command) {
    if (command === 'apilog') {
        return function (args) {
            if (args.length != 1) {
                console.log('Usage: \apilog <tid>');
                return '';
            }

            if (args[0] === '*') {
                var tids = [];
                Process.enumerateThreadsSync().forEach(function (thread) {
                    tids.push(thread['id']);
                })
                tids = tids.slice(0, tids.length - 1);
            } else {
                var tids = [];
                args[0].split(',').forEach(function (tmp) {
                    tids.push(parseInt(tmp));
                });
            }
            tids.forEach(function (tid) {
                Stalker.follow(tid, {
                    events: {
                        call: true,
                        ret: false,
                        exec: true,
                        block: true,
                        compile: false
                    },


                    /*
                                    onReceive: function (events) {
                                        console.log(Stalker.parse(events));
                                    },
                    */
                    transform: function (iterator) {
                        var instruction = iterator.next();
                        do {
                            var instrAddr = instruction.address;
                            if (instruction.mnemonic === 'call') {
                                var operand = instruction.operands[0].value;
                                if (typeof (operand) === 'number') {
                                    var apiName = DebugSymbol.fromAddress(ptr(operand));
                                    if (apiName !== undefined) {
                                        console.log(instrAddr + '\t' + instruction + '\t' + apiName);
                                    }
                                } else {
                                    var address = 0;
                                    iterator.putCallout(function (context) {
                                        address = parseInt(context[operand], 16);
                                        if (!isNaN(address)) {
                                            var apiName = DebugSymbol.fromAddress(ptr(address));
                                            if (apiName !== undefined) {
                                                console.log(instrAddr + '\t' + instruction + '\t' + apiName);
                                            }
                                        }
                                    });

                                }
                            }
                            iterator.keep();
                        }
                        while ((instruction = iterator.next()) !== null);
                    },
                });
            });

            return '[*] Stalking ' + tids + '!';

        }
    } else if (command === 'apilog-') {
        return function (args) {
            if (args.length != 1) {
                console.log('Usage: \stalky- <tid_to_unfollow>');
                return '';
            }
            if (args[0] === '*') {
                var tids = [];
                Process.enumerateThreadsSync().forEach(function (thread) {
                    tids.push(thread['id']);
                })
                tids = tids.slice(0, tids.length - 1);
                console.log(tids);
            } else {
                var tids = parseInt(args[0].split('\n'));
            }
            tids.forEach(function (tid) {
                Stalker.unfollow(tid);
            });
            return '[*] Unfollow ' + tids + '.';
        }
    }
});