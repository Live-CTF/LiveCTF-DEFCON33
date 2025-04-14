// Load all modules (if PIE, use `Module.findBaseAddress`)
const moduleName = Process.enumerateModules()[0].name;
const base = Module.findBaseAddress(moduleName);

console.log(`[+] Target module: ${moduleName} @ ${base}`);

Module.enumerateSymbols(moduleName).forEach(sym => {
    if (sym.name.startsWith("func_")) {
        try {
            Interceptor.attach(sym.address, {
                onEnter(args) {
                    console.log(`[+] Called ${sym.name} @ ${sym.address}`);
                }
            });
        } catch (err) {
            console.error(`[-] Failed to hook ${sym.name}: ${err}`);
        }
    }
});