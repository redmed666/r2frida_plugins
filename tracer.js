'use strict';

r2frida.pluginRegister('tracer', function (command) {
    if (command === 'tracer') {
        return function (args) {
            if (args.length < 2) {
                console.log('Usage: \\tracer <tid_or_wildcard> <folderpath>');
                console.log('Example: \\tracer 7212 c:/users/someone/desktop/');
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


            var filepath = args[1];
            tids.forEach(function (tid) {
                var file = new File(filepath + 'trace_' + tid + '.log', 'w');
                Stalker.follow(tid, {
                    trustThreshold: -1,
                    queueCapacity: 500000,
                    queueDrainInterval: 100,
                    events: {
                        call: false,
                        ret: false,
                        exec: true,
                        block: true,
                        compile: false
                    },
                    transform: function (iterator) {
                        var instruction = iterator.next();
                        var instructCopy = instruction;
                        var instructAddr = instruction.address;
                        do {

                            /*

                            iterator.putCallout(function (context) {
                                file.write(instructAddr + '\t' + instruction + '\t' + JSON.stringify(context) + '\n');
                                file.flush();
                            });
                            */
                            file.write(instruction.address + '\t' + instruction + '\n');
                            file.flush();
                            iterator.keep();
                        }
                        while ((instruction = iterator.next()) !== null);
                    },
                });
            });
            return '[*] Tracing ' + tids + '!';
        }
    } else if (command === 'tracer-') {
        return function (args) {
            if (args.length != 1) {
                console.log('Usage: \\tracer- <tid_to_unfollow>');
                return '';
            }
            if (args[0] === '*') {
                var tids = [];
                Process.enumerateThreadsSync().forEach(function (thread) {
                    tids.push(thread['id']);
                })
                tids = tids.slice(0, tids.length);

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