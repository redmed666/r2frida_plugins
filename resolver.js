'use strict';

r2frida.pluginRegister('resolver', function (command) {
    if (command === 'resO') {
        return function (args) {
            if (args.length < 2) {
                console.log("Usage: resO {objc, module} <query>");
                return {};
            }
            var type = args[0];
            args = args.slice(1);
            var query = args.join(' ');
            return new ApiResolver(type).enumerateMatchesSync(query)
                .map(function (match) {
                    return match.address + '\t' + match.name;
                })
                .join('\n');
        }
    }
});