# Static Object Bundler
Reference implementation for a naive static bundle object creator script that supports hiding local symbols.

**Note:** Any attempt to support stripping the symbols of localized symbols will require official `ld` support as it will require also finalizing related relocations (where possible).

## Additional Reading
* Static Bundle Object - [Part #1](https://medium.com/@eyal.itkin/the-a-file-is-a-relic-why-static-archives-were-a-bad-idea-all-along-8cd1cf6310c5) - The .a File is a Relic: Why Static Archives Were a Bad Idea All Along
* Static Bundle Object - [Part #2](https://medium.com/@eyal.itkin/static-bundle-object-modernizing-static-linking-f1be36175064) - Modernizing Static Linking
