import assert from "node:assert/strict";

import {
  computePageKeys,
  computePrivateKeyRangePage,
  decodeWif,
  privateKeyToAddresses,
  privateKeyToWif,
  totalPagesForPrivateKeyRange,
  totalPagesForResultsPerPage,
} from "../src/bitcoin.js";
import {
  formatPageNumber,
  formatPrivateKey,
  handleRequest,
  parseAddressFormats,
  parsePagePath,
  parsePageSize,
  parsePuzzleRange,
  parseRangePagePath,
  puzzleRangeBounds,
  parsePrivateKeyFormats,
  redirectLocationForPrivateKey,
  redirectLocationForWif,
  renderOptionsFromSearchParams,
  renderPage,
} from "../src/server.js";

const { test, expect } = globalThis.Bun
  ? await import("bun:test")
  : {
      test(name, fn) {
        fn();
        console.log(`ok - ${name}`);
      },
      expect(value) {
        return {
          toBe(expected) {
            assert.equal(value, expected);
          },
          toEqual(expected) {
            assert.deepEqual(value, expected);
          },
        };
      },
    };

test("derives the known Bitcoin outputs for private key 1", () => {
  const [record] = computePageKeys(1n, 1);

  expect(record.privateKey).toBe("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
  expect(record.hex).toBe("0000000000000000000000000000000000000000000000000000000000000001");
  expect(record.uncompressed).toBe("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
  expect(record.compressed).toBe("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
});

test("decodes uncompressed and compressed WIF values", () => {
  expect(decodeWif("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")).toEqual({
    privateKey: 1n,
    compressed: false,
  });
  expect(decodeWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")).toEqual({
    privateKey: 1n,
    compressed: true,
  });
});

test("uses the same page boundaries as the original directory", () => {
  const pageOne = computePageKeys(1n);
  const [firstOnPageTwo] = computePageKeys(2n);

  expect(pageOne[0].number).toBe("1");
  expect(pageOne[127].number).toBe("128");
  expect(firstOnPageTwo.number).toBe("129");
});

test("computes pages inside a private-key range", () => {
  const first = 1n << 70n;
  const last = (1n << 71n) - 1n;
  const firstPage = computePrivateKeyRangePage(1n, first, last, 128);
  const lastPage = computePrivateKeyRangePage(1n << 63n, first, last, 128);

  expect(totalPagesForPrivateKeyRange(first, last, 128)).toBe(1n << 63n);
  expect(firstPage[0].number).toBe(first.toString());
  expect(firstPage[127].number).toBe((first + 127n).toString());
  expect(lastPage[0].number).toBe(((1n << 71n) - 128n).toString());
  expect(lastPage[127].number).toBe(last.toString());
});

test("redirects a WIF to the page that contains its key", () => {
  const pageOne = computePageKeys(1n);
  const lastOnPageOne = pageOne[127];

  expect(redirectLocationForWif(lastOnPageOne.privateKey)).toBe(`/1?private=wif#${lastOnPageOne.privateKey}`);
  expect(redirectLocationForWif(lastOnPageOne.privateKey, 64)).toBe(
    `/2?private=wif&size=64#${lastOnPageOne.privateKey}`,
  );
});

test("redirects a private key lookup to the page that contains it", async () => {
  const fragment = "d2c55".padStart(64, "0");

  expect(redirectLocationForPrivateKey("0xd2c55")).toBe(`/0x1a59?private=hex#${fragment}`);
  expect(redirectLocationForPrivateKey("d2c55", 64)).toBe(`/0x34b2?private=hex&size=64#${fragment}`);
  expect(redirectLocationForPrivateKey("863359")).toBe("/6745?private=decimal#key-863359");

  const response = handleRequest(new Request("http://localhost/go/0xd2c55"));
  expect(response.status).toBe(307);
  expect(response.headers.get("location")).toBe(`/0x1a59?private=hex#${fragment}`);

  const decimalResponse = handleRequest(new Request("http://localhost/go/863359"));
  expect(decimalResponse.status).toBe(307);
  expect(decimalResponse.headers.get("location")).toBe("/6745?private=decimal#key-863359");

  const decimalPage = renderPage(6745n, { privateKeyFormats: parsePrivateKeyFormats("decimal") });
  expect(decimalPage.includes("id=\"key-863359\"")).toBe(true);
  expect(decimalPage.includes("<td>863359</td>")).toBe(true);
});

test("rejects invalid private key lookups", () => {
  expect(handleRequest(new Request("http://localhost/go/0")).status).toBe(404);
  expect(handleRequest(new Request("http://localhost/go/not-a-key")).status).toBe(404);
});

test("normalizes page paths like the Go handler", () => {
  expect(parsePagePath("/")).toBe(1n);
  expect(parsePagePath("/0")).toBe(1n);
  expect(parsePagePath("/-2")).toBe(2n);
  expect(parsePagePath("/0x10")).toBe(16n);
  expect(parsePagePath("/+0x10")).toBe(16n);
  expect(parsePagePath("/-0x10")).toBe(16n);
  expect(parsePagePath("/not-a-page")).toBe(null);
  expect(parsePagePath(`/${totalPagesForResultsPerPage(2048) + 1n}`, 2048)).toBe(null);
});

test("parses strict range page paths", () => {
  expect(parseRangePagePath("/", 10n)).toBe(1n);
  expect(parseRangePagePath("/1", 10n)).toBe(1n);
  expect(parseRangePagePath("/0xa", 10n)).toBe(10n);
  expect(parseRangePagePath("/0", 10n)).toBe(null);
  expect(parseRangePagePath("/-2", 10n)).toBe(null);
  expect(parseRangePagePath("/11", 10n)).toBe(null);
});

test("formats page navigation in decimal or hex", () => {
  expect(formatPageNumber(16n)).toBe("16");
  expect(formatPageNumber(16n, "hex")).toBe("0x10");
});

test("parses page size from the configured query setting", () => {
  expect(parsePageSize()).toBe(128);
  expect(parsePageSize("1")).toBe(1);
  expect(parsePageSize("2048")).toBe(2048);
  expect(renderOptionsFromSearchParams(new URLSearchParams("size=16")).pageSize).toBe(16);
  expect(renderOptionsFromSearchParams(new URLSearchParams("per_page=16")).pageSize).toBe(128);
  assert.throws(() => parsePageSize("0"), /Invalid page size/);
  assert.throws(() => parsePageSize("2049"), /Invalid page size/);
  assert.throws(() => parsePageSize("abc"), /Invalid page size/);
});

test("parses BTC puzzle ranges from URL parameters", () => {
  const bounds = puzzleRangeBounds(71, 128);

  expect(parsePuzzleRange("71")).toBe(71);
  expect(renderOptionsFromSearchParams(new URLSearchParams("range=71")).puzzleRange).toBe(71);
  expect(bounds.firstPrivateKey).toBe(1n << 70n);
  expect(bounds.lastPrivateKey).toBe((1n << 71n) - 1n);
  expect(bounds.totalPages).toBe(1n << 63n);
  assert.throws(() => parsePuzzleRange("0"), /Invalid range/);
  assert.throws(() => parsePuzzleRange("257"), /Invalid range/);
  assert.throws(() => parsePuzzleRange("abc"), /Invalid range/);
});

test("derives addresses directly from a private key", () => {
  expect(privateKeyToWif(1n)).toBe("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
  expect(privateKeyToAddresses(1n)).toEqual({
    uncompressed: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    compressed: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  });
});

test("formats private keys from the configured setting", () => {
  const [record] = computePageKeys(1n, 1);

  expect(parsePrivateKeyFormats()).toEqual([]);
  expect(parsePrivateKeyFormats("hex,decimal")).toEqual(["hex", "decimal"]);
  expect(parsePrivateKeyFormats("hexadecimal,dec,wif")).toEqual(["hex", "decimal", "wif"]);
  expect(parsePrivateKeyFormats("all")).toEqual(["wif", "hex", "decimal"]);
  expect(formatPrivateKey(record, parsePrivateKeyFormats("hex,decimal"))).toBe(
    "hex:0000000000000000000000000000000000000000000000000000000000000001 decimal:1",
  );
});

test("renders private keys in hex and decimal when configured", () => {
  const page = renderPage(1n, { privateKeyFormats: parsePrivateKeyFormats("hex,decimal") });

  expect(page.includes("Private Key (hex / decimal)")).toBe(true);
  expect(
    page.includes("hex:0000000000000000000000000000000000000000000000000000000000000001 decimal:1"),
  ).toBe(true);
});

test("renders only compressed addresses by default", () => {
  const page = renderPage(1n);

  expect(parseAddressFormats()).toEqual(["compressed"]);
  expect(parseAddressFormats("address,compressed")).toEqual(["uncompressed", "compressed"]);
  expect(page.includes("<th scope=\"col\">Compressed Address</th>")).toBe(true);
  expect(page.includes("<th scope=\"col\">Address</th>")).toBe(false);
  expect(page.includes("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")).toBe(false);
  expect(page.includes("https://blockchain.info/address/1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")).toBe(false);
  expect(page.includes("https://blockchain.info/address/1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")).toBe(true);
});

test("adds columns from URL parameters", () => {
  const options = renderOptionsFromSearchParams(
    new URLSearchParams("private=hex,decimal&addresses=uncompressed"),
  );
  const page = renderPage(1n, {
    ...options,
    queryString: "?private=hex,decimal&addresses=uncompressed",
  });

  expect(options.privateKeyFormats).toEqual(["hex", "decimal"]);
  expect(options.addressFormats).toEqual(["compressed", "uncompressed"]);
  expect(page.includes("<th scope=\"col\">Private Key (hex / decimal)</th>")).toBe(true);
  expect(page.includes("<th scope=\"col\">Address</th>")).toBe(true);
  expect(page.includes("<th scope=\"col\">Compressed Address</th>")).toBe(true);
  expect(
    page.includes("hex:0000000000000000000000000000000000000000000000000000000000000001 decimal:1"),
  ).toBe(true);
  expect(page.includes("https://blockchain.info/address/1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")).toBe(true);
  expect(page.includes("href=\"/2?private=hex,decimal&amp;addresses=uncompressed\"")).toBe(true);
});

test("uses a custom page size from URL parameters", async () => {
  const response = handleRequest(new Request("http://localhost/2?size=64&private=decimal"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes(`page 2 / ${totalPagesForResultsPerPage(64)}`)).toBe(true);
  expect(page.includes("<td>65</td>")).toBe(true);
  expect(page.includes("href=\"/1?size=64&amp;private=decimal\"")).toBe(true);
  expect(page.includes("href=\"/3?size=64&amp;private=decimal\"")).toBe(true);
});

test("uses range pages relative to the BTC puzzle key range", async () => {
  const firstPrivateKey = 1n << 70n;
  const lastPrivateKey = (1n << 71n) - 1n;
  const response = handleRequest(new Request("http://localhost/?range=71&private=decimal"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes(`page 1 / ${1n << 63n}`)).toBe(true);
  expect(page.includes(`range 71 from ${firstPrivateKey} to ${lastPrivateKey}`)).toBe(true);
  expect(page.includes(`<td>${firstPrivateKey}</td>`)).toBe(true);
  expect(page.includes("href=\"/1?range=71&amp;private=decimal\"")).toBe(true);
  expect(page.includes("href=\"/2?range=71&amp;private=decimal\"")).toBe(true);
});

test("omits range details from the header outside range mode", async () => {
  const response = handleRequest(new Request("http://localhost/1"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes("<span>range ")).toBe(false);
});

test("rejects pages outside a BTC puzzle range", async () => {
  const response = handleRequest(new Request(`http://localhost/${(1n << 63n) + 1n}?range=71`));
  const zeroResponse = handleRequest(new Request("http://localhost/0?range=71"));

  expect(response.status).toBe(404);
  expect(zeroResponse.status).toBe(404);
});

test("clamps range navigation at the last BTC puzzle range page", async () => {
  const lastRangePage = 1n << 63n;
  const response = handleRequest(new Request(`http://localhost/${lastRangePage}?range=71&private=decimal`));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes(`<td>${(1n << 71n) - 128n}</td>`)).toBe(true);
  expect(page.includes(`<td>${(1n << 71n) - 1n}</td>`)).toBe(true);
  expect(page.includes(`href=\"/${lastRangePage - 1n}?range=71&amp;private=decimal\"`)).toBe(true);
  expect(page.includes(`href=\"/${lastRangePage}?range=71&amp;private=decimal\"`)).toBe(true);
});

test("highlights a row when target matches an address", async () => {
  const target = "1HEhJYasEz2XWecDmEiSV79WJLv9VyixkY";
  const response = handleRequest(new Request(`http://localhost/6745?target=${target}`));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes(`<tr id="${target}" class="target-match">`)).toBe(true);
  expect(page.includes("href=\"/6744?target=1HEhJYasEz2XWecDmEiSV79WJLv9VyixkY\"")).toBe(true);
  expect(page.includes("href=\"/6746?target=1HEhJYasEz2XWecDmEiSV79WJLv9VyixkY\"")).toBe(true);
});

test("rejects invalid page sizes from URL parameters", async () => {
  const response = handleRequest(new Request("http://localhost/1?size=2049"));
  const body = await response.text();

  expect(response.status).toBe(400);
  expect(body.includes("Invalid page size")).toBe(true);
});

test("renders page navigation in hex when the page path is hex", async () => {
  const response = handleRequest(new Request("http://localhost/0x10?private=hex"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes("page 0x10 / 0x")).toBe(true);
  expect(page.includes("href=\"/0xf?private=hex\"")).toBe(true);
  expect(page.includes("href=\"/0x11?private=hex\"")).toBe(true);
  expect(page.includes("href=\"/16?private=hex\"")).toBe(true);
  expect(page.includes("<strong>hex</strong>")).toBe(true);
});

test("keeps hex navigation after entering a hex page path", async () => {
  const response = handleRequest(new Request("http://localhost/0x10?private=hex&pages=decimal"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes("page 0x10 / 0x")).toBe(true);
  expect(page.includes("href=\"/0xf?private=hex\"")).toBe(true);
  expect(page.includes("href=\"/0x11?private=hex\"")).toBe(true);
  expect(page.includes("pages=decimal")).toBe(false);
});

test("uses decimal navigation when the page path is decimal", async () => {
  const response = handleRequest(new Request("http://localhost/16?pages=hex"));
  const page = await response.text();

  expect(response.status).toBe(200);
  expect(page.includes("page 16 / ")).toBe(true);
  expect(page.includes("href=\"/15\"")).toBe(true);
  expect(page.includes("href=\"/17\"")).toBe(true);
  expect(page.includes("pages=hex")).toBe(false);
});
