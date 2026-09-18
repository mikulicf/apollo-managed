# Managed access policy tests

This standalone target compiles Apollo's production `src/managed_access.cpp` directly and exercises its public API. It intentionally does not depend on the full Apollo build.

On Ubuntu, install the small dependency set and run:

```sh
sudo apt-get update
sudo apt-get install -y cmake g++ libssl-dev nlohmann-json3-dev
cmake -S tests/managed_access -B build/managed-access-tests
cmake --build build/managed-access-tests --parallel
ctest --test-dir build/managed-access-tests --output-on-failure
```

The policy reader rate-limits filesystem reads to 500 ms. Mutation tests wait 550 ms before refreshing so they verify the public production behavior without a test-only clock or production hook.
