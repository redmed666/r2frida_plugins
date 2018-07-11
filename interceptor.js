'use strict';

r2frida.pluginRegister('interc', function (command) {
    if (command === 'interc') {
        return function (argsCmd) {
            if (argsCmd.length < 2) {
                console.log('Usage: interc <library_name> <function>');
                return '';
            }

            var f = Module.findExportByName(argsCmd[0],
                argsCmd[1]);
            Interceptor.attach(f, {
                onEnter: function (args) {
                    console.log(argsCmd[1] + ' called from:\n' +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n') + '\n');
                    console.log('Context information:');
                    console.log('Context  : ' + JSON.stringify(this.context));
                    console.log('Return   : ' + this.returnAddress);
                    console.log('ThreadId : ' + this.threadId);
                    console.log('Depth    : ' + this.depth);
                    console.log('Errornr  : ' + this.err);
                },
                onLeave: function (result) {
                    console.log("Result: " + result);
                }
            });
            return '[*] Attached!';
        };
    }
});