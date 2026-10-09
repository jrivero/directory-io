import {
  MAX_PRIVATE_KEY,
  RESULTS_PER_PAGE,
  computePageKeys,
  computePrivateKeyRangePage,
  decodeWif,
  privateKeyToWif,
  totalPagesForPrivateKeyRange,
  totalPagesForResultsPerPage,
} from "./bitcoin.js";

export const DEFAULT_PORT = 8085;
export const WARNING_PREFIX = "/warning:understand-how-this-works!/";
export const GO_PREFIX = "/go/";
export const PRIVATE_KEY_FORMATS_SETTING = "PRIVATE_KEY_FORMATS";
export const ADDRESS_FORMATS_SETTING = "ADDRESS_FORMATS";

const DEFAULT_PRIVATE_KEY_FORMATS = [];
const DEFAULT_ADDRESS_FORMATS = ["compressed"];
const DEFAULT_PAGE_FORMAT = "decimal";
const DEFAULT_PAGE_SIZE = Number(RESULTS_PER_PAGE);
const MIN_PAGE_SIZE = 1;
const MAX_PAGE_SIZE = 2048;
const ALL_PRIVATE_KEY_FORMATS = ["wif", "hex", "decimal"];
const ALL_ADDRESS_FORMATS = ["uncompressed", "compressed"];

const PRIVATE_KEY_FORMAT_ALIASES = new Map([
  ["wif", "wif"],
  ["hex", "hex"],
  ["hexadecimal", "hex"],
  ["decimal", "decimal"],
  ["dec", "decimal"],
]);
const ADDRESS_FORMAT_ALIASES = new Map([
  ["address", "uncompressed"],
  ["uncompressed", "uncompressed"],
  ["compressed", "compressed"],
  ["compressed-address", "compressed"],
  ["compressed_address", "compressed"],
]);
const PRIVATE_KEY_FORMAT_LABELS = {
  wif: "WIF",
  hex: "hex",
  decimal: "decimal",
};
const ADDRESS_FORMAT_LABELS = {
  uncompressed: "Address",
  compressed: "Compressed Address",
};
const PRIVATE_KEY_QUERY_PARAMS = ["private", "private_key", "private-key", "privateKey", "private_key_formats", "private-key-formats", "privateKeyFormats"];
const ADDRESS_QUERY_PARAMS = ["addresses", "address", "address_formats", "address-formats", "addressFormats"];
const LEGACY_PAGE_FORMAT_QUERY_PARAMS = ["pages", "page_format", "page-format", "pageFormat", "page_numbers", "page-numbers", "pageNumbers"];
const PAGE_SIZE_QUERY_PARAMS = ["size"];
const TARGET_QUERY_PARAMS = ["target"];
const RANGE_QUERY_PARAMS = ["range"];
const MIN_PUZZLE_RANGE = 1;
const MAX_PUZZLE_RANGE = MAX_PRIVATE_KEY.toString(2).length;

function parseFormatList(setting, { defaultFormats, allFormats, aliases, settingName, validFormats }) {
  const rawSetting = `${setting ?? ""}`.trim();
  if (rawSetting === "") {
    return [...defaultFormats];
  }

  const formats = [];
  const invalidFormats = [];
  let sawExplicitFormat = false;

  for (const rawFormat of rawSetting.split(",")) {
    const normalizedFormat = rawFormat.trim().toLowerCase();
    if (normalizedFormat === "") {
      continue;
    }

    sawExplicitFormat = true;
    if (normalizedFormat === "none" || normalizedFormat === "off") {
      formats.length = 0;
      continue;
    }

    if (normalizedFormat === "all" || normalizedFormat === "both") {
      for (const format of allFormats) {
        if (!formats.includes(format)) {
          formats.push(format);
        }
      }
      continue;
    }

    const format = aliases.get(normalizedFormat);
    if (!format) {
      invalidFormats.push(rawFormat.trim());
      continue;
    }

    if (!formats.includes(format)) {
      formats.push(format);
    }
  }

  if (invalidFormats.length > 0) {
    throw new Error(`Invalid ${settingName}: ${invalidFormats.join(", ")}. Use ${validFormats}.`);
  }

  return sawExplicitFormat ? formats : [...defaultFormats];
}

export function parsePrivateKeyFormats(setting = "") {
  return parseFormatList(setting, {
    defaultFormats: DEFAULT_PRIVATE_KEY_FORMATS,
    allFormats: ALL_PRIVATE_KEY_FORMATS,
    aliases: PRIVATE_KEY_FORMAT_ALIASES,
    settingName: PRIVATE_KEY_FORMATS_SETTING,
    validFormats: "wif, hex, decimal, all, or none",
  });
}

export function parseAddressFormats(setting = "") {
  return parseFormatList(setting, {
    defaultFormats: DEFAULT_ADDRESS_FORMATS,
    allFormats: ALL_ADDRESS_FORMATS,
    aliases: ADDRESS_FORMAT_ALIASES,
    settingName: ADDRESS_FORMATS_SETTING,
    validFormats: "uncompressed, compressed, all, or none",
  });
}

export function parsePageSize(setting = "") {
  const rawSetting = `${setting ?? ""}`.trim();
  if (rawSetting === "") {
    return DEFAULT_PAGE_SIZE;
  }

  if (!/^\d+$/.test(rawSetting)) {
    throw new Error(`Invalid page size: ${rawSetting}. Use an integer from 1 to 2048.`);
  }

  const pageSize = Number.parseInt(rawSetting, 10);
  if (pageSize < MIN_PAGE_SIZE || pageSize > MAX_PAGE_SIZE) {
    throw new Error(`Invalid page size: ${rawSetting}. Use an integer from 1 to 2048.`);
  }

  return pageSize;
}

export function parsePuzzleRange(setting = "") {
  const rawSetting = `${setting ?? ""}`.trim();
  if (!/^\d+$/.test(rawSetting)) {
    throw new Error(`Invalid range: ${rawSetting}. Use an integer from ${MIN_PUZZLE_RANGE} to ${MAX_PUZZLE_RANGE}.`);
  }

  const range = Number.parseInt(rawSetting, 10);
  if (!Number.isSafeInteger(range) || range < MIN_PUZZLE_RANGE || range > MAX_PUZZLE_RANGE) {
    throw new Error(`Invalid range: ${rawSetting}. Use an integer from ${MIN_PUZZLE_RANGE} to ${MAX_PUZZLE_RANGE}.`);
  }

  return range;
}

function parseTarget(setting = "") {
  const target = `${setting ?? ""}`.trim();
  return target === "" ? null : target;
}

function parsePrivateKeyLookup(value) {
  const rawValue = `${value ?? ""}`.trim();
  if (rawValue === "") {
    throw new Error("Invalid private key");
  }

  let privateKey;
  let format;
  if (/^0x[0-9a-f]+$/i.test(rawValue)) {
    privateKey = BigInt(rawValue);
    format = "hex";
  } else if (/^\d+$/.test(rawValue)) {
    privateKey = BigInt(rawValue);
    format = "decimal";
  } else if (/^[0-9a-f]+$/i.test(rawValue)) {
    privateKey = BigInt(`0x${rawValue}`);
    format = "hex";
  } else {
    privateKey = decodeWif(rawValue).privateKey;
    format = "wif";
  }

  if (privateKey < 1n || privateKey > MAX_PRIVATE_KEY) {
    throw new Error("Invalid private key");
  }

  return { privateKey, format };
}

const CONFIGURED_PRIVATE_KEY_FORMATS = parsePrivateKeyFormats(globalThis.process?.env?.[PRIVATE_KEY_FORMATS_SETTING]);
const CONFIGURED_ADDRESS_FORMATS = parseAddressFormats(globalThis.process?.env?.[ADDRESS_FORMATS_SETTING]);

const PAGE_HEADER = `<!doctype html>
<html>
<head>
\t<title>Bitcoin private keys</title>
\t<meta charset="utf-8" />
\t<meta name="viewport" content="width=device-width, initial-scale=1" />
\t<style>
\t\tbody {
\t\t\tmargin: 24px;
\t\t\tbackground: #fff;
\t\t\tcolor: #111;
\t\t\tfont: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
\t\t}
\t\ta {
\t\t\tcolor: inherit;
\t\t\ttext-decoration: none;
\t\t\tborder-bottom: 1px solid #d7d7d7;
\t\t}
\t\ta:hover { border-color: #111; }
\t\theader, footer {
\t\t\tdisplay: flex;
\t\t\tgap: 12px;
\t\t\talign-items: baseline;
\t\t\tcolor: #666;
\t\t}
\t\theader { margin-bottom: 18px; }
\t\tfooter { margin-top: 18px; }
\t\tstrong {
\t\t\tcolor: #111;
\t\t\tfont-weight: 600;
\t\t}
\t\ttable {
\t\t\tborder-collapse: collapse;
\t\t\twidth: auto;
\t\t}
\t\tth, td {
\t\t\tpadding: 2px 12px 2px 8px;
\t\t\ttext-align: left;
\t\t\twhite-space: nowrap;
\t\t}
\t\tth {
\t\t\tborder-bottom: 1px solid #e2e2e2;
\t\t\tcolor: #666;
\t\t\tfont-weight: 400;
\t\t}
\t\ttr:target td {
\t\t\tbackground: #ffe15a;
\t\t}
\t\ttr.target-match td {
\t\t\tbackground: #006b3a;
\t\t\tcolor: #fff;
\t\t\tfont-weight: 600;
\t\t}
\t\ttr.target-match a {
\t\t\tcolor: #fff;
\t\t\tborder-color: rgba(255, 255, 255, 0.65);
\t\t}
\t\tdialog {
\t\t\tmax-width: 640px;
\t\t\tborder: 1px solid #d7d7d7;
\t\t\tfont: inherit;
\t\t\twhite-space: normal;
\t\t}
\t\tdialog form { text-align: right; }
\t\ttr.target-match:target td {
\t\t\tbackground: #006b3a;
\t\t\tcolor: #fff;
\t\t}
\t</style>
</head>
<body>
<header>
\t<span>page %PAGE% / %PAGES%</span>
\t%RANGE_DETAILS%
\t<span>pages %PAGE_FORMAT_SWITCH%</span>
\t<a href="%PREVIOUS_HREF%">previous</a>
\t<a href="%NEXT_HREF%">next</a>
\t<a href="#help" onclick="event.preventDefault(); help.showModal()">hacking parameters</a>
</header>
<dialog id="help">
\t<form method="dialog"><button>close</button></form>
\t<p>Add columns with URL parameters:</p>
\t<ul>
\t\t<li><code>?private=wif</code></li>
\t\t<li><code>?private=hex,decimal</code></li>
\t\t<li><code>?addresses=uncompressed</code></li>
\t\t<li><code>?private=hex,decimal&amp;addresses=uncompressed</code></li>
\t</ul>
\t<p>Pages show 128 keys by default. Use <code>?size=64</code> to change the page size. Accepted values are integers from 1 to 2048.</p>
\t<p>Limit navigation to a BTC puzzle key range with <code>?range=&lt;n&gt;</code>. Pages are relative to that range: <code>/?range=71</code> starts at 2^70, <code>/2?range=71</code> shows the next page, and pages outside the range return 404. Ranges use 2^(n-1) through 2^n - 1.</p>
\t<p>Highlight a row by Bitcoin address with <code>?target=&lt;address&gt;</code>, for example <code>/6745?target=1HEhJYasEz2XWecDmEiSV79WJLv9VyixkY</code>.</p>
\t<p>Page navigation is decimal by default. Open a hex path such as <code>/0x10</code> to navigate in hexadecimal; <code>/16</code> navigates in decimal.</p>
\t<p>Jump to the page containing a private key with <code>/go/&lt;private-key&gt;</code>: <code>/go/0xd2c55</code> uses hex output, <code>/go/863359</code> decimal. <code>?size=64</code> also works on <code>/go/...</code>.</p>
</dialog>
<main>
`;

const PAGE_FOOTER = `</main>
<footer>
\t<a href="%PREVIOUS_HREF%">previous</a>
\t<a href="%NEXT_HREF%">next</a>
</footer>
</body>
</html>`;

export function parsePagePath(pathname, pageSize = DEFAULT_PAGE_SIZE) {
  if (pathname === "/" || pathname === "") {
    return 1n;
  }

  const rawPage = pathname.slice(1);
  if (!/^[+-]?(?:0x[0-9a-f]+|\d+)$/i.test(rawPage)) {
    return null;
  }

  const sign = rawPage.startsWith("-") ? -1n : 1n;
  const unsignedPage = rawPage.startsWith("-") || rawPage.startsWith("+") ? rawPage.slice(1) : rawPage;
  let page;
  try {
    page = BigInt(unsignedPage) * sign;
  } catch {
    return null;
  }

  if (page < 0n) {
    page = -page;
  }

  if (page < 1n) {
    page = 1n;
  }

  if (page > totalPagesForResultsPerPage(pageSize)) {
    return null;
  }

  return page;
}

export function parseRangePagePath(pathname, totalPages) {
  if (pathname === "/" || pathname === "") {
    return 1n;
  }

  const rawPage = pathname.slice(1);
  if (!/^(?:0x[0-9a-f]+|[1-9]\d*)$/i.test(rawPage)) {
    return null;
  }

  let page;
  try {
    page = BigInt(rawPage);
  } catch {
    return null;
  }

  if (page < 1n || page > totalPages) {
    return null;
  }

  return page;
}

export function puzzleRangeBounds(range, pageSize = DEFAULT_PAGE_SIZE) {
  const puzzleRange = typeof range === "number" ? range : parsePuzzleRange(range);
  const firstPrivateKey = 1n << BigInt(puzzleRange - 1);
  const lastCandidate = (1n << BigInt(puzzleRange)) - 1n;
  const lastPrivateKey = lastCandidate > MAX_PRIVATE_KEY ? MAX_PRIVATE_KEY : lastCandidate;

  return {
    range: puzzleRange,
    firstPrivateKey,
    lastPrivateKey,
    totalPages: totalPagesForPrivateKeyRange(firstPrivateKey, lastPrivateKey, pageSize),
  };
}

function pageFormatFromPath(pathname) {
  const rawPage = pathname.slice(1);
  return /^[+-]?0x/i.test(rawPage) ? "hex" : "decimal";
}

function firstQuerySetting(searchParams, names) {
  for (const name of names) {
    if (!searchParams.has(name)) {
      continue;
    }

    return searchParams
      .getAll(name)
      .map((value) => value.trim())
      .filter(Boolean)
      .join(",");
  }

  return null;
}

function settingClearsFormats(setting) {
  return `${setting ?? ""}`.split(",").some((format) => ["none", "off"].includes(format.trim().toLowerCase()));
}

function mergeFormats(baseFormats, addedFormats) {
  const formats = [...baseFormats];
  for (const format of addedFormats) {
    if (!formats.includes(format)) {
      formats.push(format);
    }
  }

  return formats;
}

export function renderOptionsFromSearchParams(searchParams) {
  const privateKeySetting = firstQuerySetting(searchParams, PRIVATE_KEY_QUERY_PARAMS);
  const addressSetting = firstQuerySetting(searchParams, ADDRESS_QUERY_PARAMS);
  const pageSizeSetting = firstQuerySetting(searchParams, PAGE_SIZE_QUERY_PARAMS);
  const targetSetting = firstQuerySetting(searchParams, TARGET_QUERY_PARAMS);
  const rangeSetting = firstQuerySetting(searchParams, RANGE_QUERY_PARAMS);
  const privateKeyFormats = privateKeySetting === null ? CONFIGURED_PRIVATE_KEY_FORMATS : parsePrivateKeyFormats(privateKeySetting);
  const addressFormats = addressSetting === null ? CONFIGURED_ADDRESS_FORMATS : parseAddressFormats(addressSetting);
  const pageSize = pageSizeSetting === null ? DEFAULT_PAGE_SIZE : parsePageSize(pageSizeSetting);
  const target = targetSetting === null ? null : parseTarget(targetSetting);
  const puzzleRange = rangeSetting === null ? null : parsePuzzleRange(rangeSetting);

  return {
    privateKeyFormats: privateKeySetting === null || settingClearsFormats(privateKeySetting) ? privateKeyFormats : mergeFormats(CONFIGURED_PRIVATE_KEY_FORMATS, privateKeyFormats),
    addressFormats: addressSetting === null || settingClearsFormats(addressSetting) ? addressFormats : mergeFormats(CONFIGURED_ADDRESS_FORMATS, addressFormats),
    pageSize,
    target,
    puzzleRange,
  };
}

function formatPrivateKeyPart(record, format) {
  if (format === "wif") {
    return record.privateKey;
  }

  if (format === "hex") {
    return record.hex;
  }

  return record.number;
}

export function formatPrivateKey(record, formats = DEFAULT_PRIVATE_KEY_FORMATS) {
  if (formats.length === 1) {
    return formatPrivateKeyPart(record, formats[0]);
  }

  return formats.map((format) => `${PRIVATE_KEY_FORMAT_LABELS[format].toLowerCase()}:${formatPrivateKeyPart(record, format)}`).join(" ");
}

function privateKeyHeader(formats) {
  if (formats.length === 1 && formats[0] === "wif") {
    return "Private Key";
  }

  return `Private Key (${formats.map((format) => PRIVATE_KEY_FORMAT_LABELS[format]).join(" / ")})`;
}

function escapeHtml(value) {
  return `${value}`.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

export function formatPageNumber(page, pageFormat = DEFAULT_PAGE_FORMAT) {
  return pageFormat === "hex" ? `0x${page.toString(16)}` : page.toString();
}

function formatPrivateKeyHex(privateKey) {
  return privateKey.toString(16).padStart(64, "0");
}

function pageHref(page, queryString, pageFormat) {
  return `/${formatPageNumber(page, pageFormat)}${queryString}`;
}

function stripLegacyPageFormatQueryString(queryString) {
  const searchParams = new URLSearchParams(queryString);
  let stripped = false;
  for (const name of LEGACY_PAGE_FORMAT_QUERY_PARAMS) {
    if (searchParams.has(name)) {
      stripped = true;
    }
    searchParams.delete(name);
  }

  if (!stripped) {
    return queryString;
  }

  const nextQueryString = searchParams.toString();
  return nextQueryString === "" ? "" : `?${nextQueryString}`;
}

function pageFormatSwitch(page, queryString, pageFormat) {
  return ["decimal", "hex"]
    .map((format) => {
      const label = format === "hex" ? "hex" : "decimal";
      if (format === pageFormat) {
        return `<strong>${label}</strong>`;
      }

      const href = pageHref(page, queryString, format);
      return `<a href="${escapeHtml(href)}">${label}</a>`;
    })
    .join(" ");
}

function rangeDetails(rangeBounds) {
  if (rangeBounds === null) {
    return "";
  }

  return `<span>range ${rangeBounds.range} from ${rangeBounds.firstPrivateKey} to ${rangeBounds.lastPrivateKey}</span>`;
}

function pageHeader(page, previous, next, queryString, pageFormat, totalPages, rangeBounds = null) {
  return PAGE_HEADER.replaceAll("%PAGE%", formatPageNumber(page, pageFormat))
    .replaceAll("%PAGES%", formatPageNumber(totalPages, pageFormat))
    .replaceAll("%RANGE_DETAILS%", rangeDetails(rangeBounds))
    .replaceAll("%PAGE_FORMAT_SWITCH%", pageFormatSwitch(page, queryString, pageFormat))
    .replaceAll("%PREVIOUS_HREF%", escapeHtml(pageHref(previous, queryString, pageFormat)))
    .replaceAll("%NEXT_HREF%", escapeHtml(pageHref(next, queryString, pageFormat)));
}

function pageFooter(previous, next, queryString, pageFormat) {
  return PAGE_FOOTER.replaceAll("%PREVIOUS_HREF%", escapeHtml(pageHref(previous, queryString, pageFormat))).replaceAll("%NEXT_HREF%", escapeHtml(pageHref(next, queryString, pageFormat)));
}

function privateKeyColumn(privateKeyFormats) {
  if (privateKeyFormats.length === 0) {
    return null;
  }

  return {
    header: privateKeyHeader(privateKeyFormats),
    cell(record) {
      return escapeHtml(formatPrivateKey(record, privateKeyFormats));
    },
  };
}

function addressColumn(format) {
  const recordKey = format === "compressed" ? "compressed" : "uncompressed";

  return {
    header: ADDRESS_FORMAT_LABELS[format],
    cell(record) {
      const address = record[recordKey];
      const href = `https://blockchain.info/address/${address}`;

      return `<a href="${escapeHtml(href)}">${escapeHtml(address)}</a>`;
    },
  };
}

function tableColumns(privateKeyFormats, addressFormats) {
  const columns = [];
  const privateColumn = privateKeyColumn(privateKeyFormats);
  if (privateColumn) {
    columns.push(privateColumn);
  }

  for (const format of addressFormats) {
    columns.push(addressColumn(format));
  }

  return columns.length > 0 ? columns : [addressColumn("compressed")];
}

function rowId(record, privateKeyFormats) {
  if (privateKeyFormats.includes("wif")) {
    return record.privateKey;
  }

  if (privateKeyFormats.includes("hex")) {
    return record.hex;
  }

  if (privateKeyFormats.includes("decimal")) {
    return `key-${record.number}`;
  }

  return record.compressed;
}

function isTargetMatch(record, target) {
  return target !== null && (record.compressed === target || record.uncompressed === target);
}

function renderTable(records, columns, privateKeyFormats, target = null) {
  const header = columns.map((column) => `<th scope="col">${escapeHtml(column.header)}</th>`).join("");
  const body = records.map((record) => {
    const className = isTargetMatch(record, target) ? " class=\"target-match\"" : "";
    return `<tr id="${escapeHtml(rowId(record, privateKeyFormats))}"${className}>${columns.map((column) => `<td>${column.cell(record)}</td>`).join("")}</tr>`;
  }).join("\n");

  return `<table>
<thead><tr>${header}</tr></thead>
<tbody>
${body}
</tbody>
</table>
`;
}

export function renderPage(page, { privateKeyFormats = CONFIGURED_PRIVATE_KEY_FORMATS, addressFormats = CONFIGURED_ADDRESS_FORMATS, pageFormat = DEFAULT_PAGE_FORMAT, pageSize = DEFAULT_PAGE_SIZE, queryString = "", target = null, puzzleRange = null, rangeBounds = null } = {}) {
  const activeRangeBounds = rangeBounds ?? (puzzleRange === null ? null : puzzleRangeBounds(puzzleRange, pageSize));
  const totalPages = activeRangeBounds === null ? totalPagesForResultsPerPage(pageSize) : activeRangeBounds.totalPages;
  const previous = activeRangeBounds === null ? page - 1n : page > 1n ? page - 1n : 1n;
  const next = activeRangeBounds === null ? page + 1n : page < totalPages ? page + 1n : totalPages;
  const records =
    activeRangeBounds === null
      ? computePageKeys(page, pageSize)
      : computePrivateKeyRangePage(page, activeRangeBounds.firstPrivateKey, activeRangeBounds.lastPrivateKey, pageSize);
  const columns = tableColumns(privateKeyFormats, addressFormats);

  return `${pageHeader(page, previous, next, queryString, pageFormat, totalPages, activeRangeBounds)}${renderTable(records, columns, privateKeyFormats, target)}${pageFooter(previous, next, queryString, pageFormat)}`;
}

export function redirectLocationForWif(wif, pageSize = DEFAULT_PAGE_SIZE) {
  const { privateKey } = decodeWif(wif);
  const page = (privateKey - 1n) / BigInt(pageSize) + 1n;
  const fragment = privateKeyToWif(privateKey, false);
  const queryParams = new URLSearchParams({ private: "wif" });
  if (pageSize !== DEFAULT_PAGE_SIZE) {
    queryParams.set("size", `${pageSize}`);
  }

  return `/${page.toString()}?${queryParams.toString()}#${fragment}`;
}

export function redirectLocationForPrivateKey(value, pageSize = DEFAULT_PAGE_SIZE) {
  const { privateKey, format } = parsePrivateKeyLookup(value);
  const page = (privateKey - 1n) / BigInt(pageSize) + 1n;
  const pageFormat = format === "hex" ? "hex" : "decimal";
  const privateFormat = format === "wif" ? "wif" : format;
  let fragment;
  if (format === "hex") {
    fragment = formatPrivateKeyHex(privateKey);
  } else if (format === "decimal") {
    fragment = `key-${privateKey.toString()}`;
  } else {
    fragment = privateKeyToWif(privateKey, false);
  }

  const queryParams = new URLSearchParams({ private: privateFormat });
  if (pageSize !== DEFAULT_PAGE_SIZE) {
    queryParams.set("size", `${pageSize}`);
  }

  return `/${formatPageNumber(page, pageFormat)}?${queryParams.toString()}#${fragment}`;
}

function notFound() {
  return new Response("404 page not found\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

function badRequest(error) {
  return new Response(`${error.message}\n`, {
    status: 400,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export function handleRequest(request) {
  const url = new URL(request.url);

  if (url.pathname.startsWith(GO_PREFIX)) {
    let pageSize;
    try {
      pageSize = parsePageSize(firstQuerySetting(url.searchParams, PAGE_SIZE_QUERY_PARAMS) ?? "");
    } catch (error) {
      return badRequest(error);
    }

    try {
      return new Response(null, {
        status: 307,
        headers: {
          location: redirectLocationForPrivateKey(decodeURIComponent(url.pathname.slice(GO_PREFIX.length)), pageSize),
        },
      });
    } catch {
      return notFound();
    }
  }

  if (url.pathname.startsWith(WARNING_PREFIX)) {
    let pageSize;
    try {
      pageSize = parsePageSize(firstQuerySetting(url.searchParams, PAGE_SIZE_QUERY_PARAMS) ?? "");
    } catch (error) {
      return badRequest(error);
    }

    try {
      return new Response(null, {
        status: 307,
        headers: {
          location: redirectLocationForWif(decodeURIComponent(url.pathname.slice(WARNING_PREFIX.length)), pageSize),
        },
      });
    } catch {
      return notFound();
    }
  }

  let renderOptions;
  try {
    renderOptions = renderOptionsFromSearchParams(url.searchParams);
  } catch (error) {
    return badRequest(error);
  }

  const rangeBounds =
    renderOptions.puzzleRange === null ? null : puzzleRangeBounds(renderOptions.puzzleRange, renderOptions.pageSize);
  const page =
    rangeBounds === null
      ? parsePagePath(url.pathname, renderOptions.pageSize)
      : parseRangePagePath(url.pathname, rangeBounds.totalPages);

  if (page === null) {
    return notFound();
  }

  return new Response(
    renderPage(page, {
      ...renderOptions,
      pageFormat: pageFormatFromPath(url.pathname),
      rangeBounds,
      queryString: stripLegacyPageFormatQueryString(url.search),
    }),
    {
      headers: { "content-type": "text/html; charset=utf-8" },
    },
  );
}

if (typeof Bun !== "undefined" && import.meta.main) {
  const port = Number.parseInt(process.env.PORT ?? `${DEFAULT_PORT}`, 10);
  const server = Bun.serve({
    port,
    fetch: handleRequest,
  });

  console.log(`Listening on http://localhost:${server.port}`);
}
