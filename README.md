# Crypto Utils

A set of utilities to perform encryption and decryption.

Currently supports AES-GCM encryption with a password.

## Notes

The project is structured in a way that both the `jvm` and `android` modules share the same
source sets in `common`. When developing using IntelliJ, the `jvm` module will seem unable to
find these sources. This is a limitation of the IDE; Gradle compiles the modules independently,
so it won't be a problem. I doubt JetBrains will bother taking care of this any time soon, so
for the time being, if you need to do any development in the `jvm` module just comment out the
`:android` module in settings.gradle.
