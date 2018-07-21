'use strict';

r2frida.pluginRegister('stalky', function (command) {
    if (command === 'stalky') {
        return function (args) {
            if (args.length < 2) {
                console.log('Usage: \stalky <tid_or_wildcard> <mnemonic_types> (<regs>)');
                console.log('Example: \stalky 7212 call,jmp eax,ebx,edx');
                return '';
            }
            if (args[0] === '*') {
                var tids = [];
                Process.enumerateThreadsSync().forEach(function (thread) {
                    tids.push(thread['id']);
                })
                tids = tids.slice(0, tids.length);
            } else {
                var tids = [];
                args[0].split(',').forEach(function (tmp) {
                    tids.push(parseInt(tmp));
                });
            }
            var mnemonicTypes = args[1].split(',');
            var regs = undefined;
            if (args.length > 2) {
                regs = args[2].split(',');
            }

            tids.forEach(function (tid) {
                Stalker.follow(tid, {
                    events: {
                        call: true,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: false
                    },


                    onCallSummary: function (summary) {},

                    transform: function (iterator) {
                        var instruction = iterator.next();

                        do {
                            if ((mnemonicTypes.indexOf(instruction.mnemonic) > -1)) {
                                if (regs) {
                                    if (regs.indexOf(instruction.operands[0].value) > -1) {
                                        console.log(instruction.address + '\t' + instruction);
                                        iterator.putCallout(function (context) {
                                            console.log(JSON.stringify(context))
                                        });
                                    }
                                } else {
                                    console.log(instruction.address + '\t' + instruction);
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
    } else if (command === 'stalky-') {
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
                tids = tids.slice(0, tids.length);
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