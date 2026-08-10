# Contributing

Small fixes are welcome. For a larger change, open an issue first so we do not build the same thing twice.

Run this before sending a pull request:

```bash
npm install
npm run check
```

If you add or change a detection rule, include a test that should match and one that should not. Only use obviously fake credentials in tests.
