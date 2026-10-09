directory.io fork
=================

This project now runs on [Bun](https://bun.sh/) and does not require Go dependencies.

##### Install Bun
```bash
curl -fsSL https://bun.sh/install | bash
```

##### Run
```bash
bun run start
```

By default, it listens on port 8085: [http://localhost:8085](http://localhost:8085)

To use a different port:
```bash
PORT=3000 bun run start
```

By default, pages render a minimal table with only compressed addresses.

Add columns with URL parameters:

- `?private=wif`
- `?private=hex,decimal`
- `?addresses=uncompressed`
- `?private=hex,decimal&addresses=uncompressed`

Pages show 128 keys by default. Use `?size=64` to change the page size. Accepted values are integers from `1` to `2048`.

Limit navigation to a BTC puzzle key range with `?range=<n>`. In range mode, pages are relative to that puzzle range: `/?range=71` starts at `2^70`, `/2?range=71` shows the next page, and pages outside the range return 404. Ranges use `2^(n-1)` through `2^n - 1`.

Highlight a row by Bitcoin address with `?target=<address>`, for example `/6745?target=1HEhJYasEz2XWecDmEiSV79WJLv9VyixkY`.

Page navigation is decimal by default. Open a page with a hex path such as `/0x10` to navigate in hexadecimal; open the same page as `/16` to navigate in decimal.

Jump directly to the page containing a private key with `/go/<private-key>`. For example, `/go/0xd2c55` redirects with hex page/private-key output, while `/go/863359` redirects with decimal page/private-key output. `?size=64` also works on `/go/...`.

You can also change server defaults with environment settings. `PRIVATE_KEY_FORMATS` accepts `wif`, `hex`, `decimal`, `all`, or `none`. `ADDRESS_FORMATS` accepts `uncompressed`, `compressed`, `all`, or `none`.

##### Development
```bash
bun run dev
```

##### Test
```bash
bun test
```
