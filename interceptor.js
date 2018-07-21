'use strict';

r2frida.pluginRegister('interc', function (command) {
    if (command === 'interc') {
        return function (argsCmd) {
            if (argsCmd.length < 3) {
                console.log('Usage: interc <library_name> <function> <nmb_args_fn> <fmt> (<index_arg:new_values>)\n');
                console.log('Example: \\interc USER32.DLL MessageBoxW 4 %d,%S,%S,%d 2:0x12345678,3:0x30\n');
                return '';
            }

            var f = Module.findExportByName(argsCmd[0],
                argsCmd[1]);
            var format = argsCmd[3].split(',');
            Interceptor.attach(f, {
                onEnter: function (args) {
                    console.log('\n===============');
                    console.log('1. ' + argsCmd[1] + ' called from:\n' +
                        Thread.backtrace(this.context, Backtracer.FUZZY)
                        .map(DebugSymbol.fromAddress).join('\n'));

                    console.log('\n2. Base Arguments:');
                    for (var i = 0; i < argsCmd[2]; i++) {
                        this.args = [];
                        this.args[i] = args[i];
                        switch (format[i]) {
                            case '%d':
                                console.log(this.args[i].toInt32());
                                break;
                            case '%s':
                                console.log(Memory.readCString(this.args[i]));
                                break;
                            case '%S':
                                console.log(Memory.readUtf16String(this.args[i]));
                                break;
                            default:
                                console.log(this.args[i]);
                                break;
                        }
                    }
                    if (argsCmd[4]) {
                        var newArgs = argsCmd[4].split(',');
                        newArgs.forEach(function (newArg) {
                            var indexArg = newArg.split(':');
                            var index = parseInt(indexArg[0]);
                            var arg = indexArg[1];
                            args[index] = ptr(arg);
                        });
                    }
                    console.log('\n3. Context information:');
                    console.log('Context  : ' + JSON.stringify(this.context));
                    console.log('Return   : ' + this.returnAddress);
                    console.log('ThreadId : ' + this.threadId);
                    console.log('Depth    : ' + this.depth);
                    console.log('Errornr  : ' + this.err);
                },
                onLeave: function (result) {
                    console.log('\n4. Result for ' + argsCmd[1] + ':');
                    console.log(result);
                    console.log('===============\n');
                }
            });
            return '[*] Attached!';
        };
    } else if (command === 'interc-') {
        return function (args) {
            Interceptor.detachAll();
            return '';
        }
    }
});