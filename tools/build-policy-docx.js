// Builds the Nerdio-branded .docx of the Threat Modelling Policy from its Markdown source,
// so the Markdown in policy/ stays the single source of truth.
//   node tools/build-policy-docx.js [in.md] [out.docx]
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, ShadingType,
  BorderStyle, AlignmentType, Header, Footer, PageNumber, TabStopType, LevelFormat, HeadingLevel, TableLayoutType,
} = require("docx");

const NAVY = "1B2E5A", BLUE = "0066CC", TEAL = "00B4A0", WHITE = "FFFFFF", BODY = "1A1A1A", ALT = "EEF2F8";
const FONT = "Arial";
const CONTENT_W = 9360; // US Letter, 1" margins

const src = process.argv[2] || path.join(__dirname, "../policy/ISMS-DEV-004-threat-modeling-policy.md");
const out = process.argv[3] || path.join(__dirname, "../dist/ISMS-DEV-004 Nerdio Threat Modelling Policy v1.0.docx");
const md = fs.readFileSync(src, "utf8").split(/\r?\n/);

const META = { title: "Threat Modelling Policy", standard: "ISO 27001:2022 · NIST SSDF · MS SDL",
  id: "ISMS-DEV-004", version: "1.0", year: "2026" };

// ---------------------------------------------------------------- inline runs
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|_[^_]+_(?=\s|$|[.,;:)]))/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), font: FONT, ...base }));
    const tok = m[0];
    if (tok.startsWith("**")) out.push(new TextRun({ text: tok.slice(2, -2), bold: true, font: FONT, ...base }));
    else if (tok.startsWith("`")) out.push(new TextRun({ text: tok.slice(1, -1), font: FONT, color: BLUE, ...base }));
    else out.push(new TextRun({ text: tok.slice(1, -1), italics: true, font: FONT, ...base }));
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), font: FONT, ...base }));
  return out;
}

// ---------------------------------------------------------------- tables
const cellBorder = { style: BorderStyle.SINGLE, size: 4, color: "C9D1E0" };
function table(rows) {
  const cells = rows.map((r) => r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
  const header = cells[0], body = cells.slice(2);
  const n = header.length;
  const longestWord = (t) => Math.max(0, ...t.replace(/[`*]/g, "").split(/\s+/).map((w) => w.length));
  const all = cells.filter((_, k) => k !== 1);
  // minimum: longest unbreakable word (~115 DXA/char at 10pt bold) + cell padding
  const minW = header.map((_, i) => Math.min(2600, 260 + 115 * Math.max(...all.map((r) => longestWord(r[i] || "")))));
  const weight = header.map((_, i) => Math.min(60, Math.max(4, ...all.map((r) => (r[i] || "").length))));
  const spare = Math.max(0, CONTENT_W - minW.reduce((a, b) => a + b, 0));
  const wsum = weight.reduce((a, b) => a + b, 0);
  const widths = minW.map((m, i) => Math.floor(m + (weight[i] / wsum) * spare));
  widths[n - 1] += CONTENT_W - widths.reduce((a, b) => a + b, 0);

  const mk = (txt, i, isHead, shade) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    borders: { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder },
    shading: { type: ShadingType.CLEAR, color: "auto", fill: isHead ? NAVY : shade },
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    children: [new Paragraph({ spacing: { before: 0, after: 0 },
      children: runs(txt, isHead ? { bold: true, color: WHITE, size: 20 } : { size: 20, color: BODY }) })],
  });
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    rows: [
      new TableRow({ tableHeader: true, children: header.map((h, i) => mk(h, i, true)) }),
      ...body.map((r, k) => new TableRow({ cantSplit: true,
        children: header.map((_, i) => mk(r[i] || "", i, false, k % 2 ? ALT : WHITE)) })),
    ],
  });
}

// ---------------------------------------------------------------- body
const children = [];
let listInstance = 0;
for (let i = 0; i < md.length; i++) {
  const line = md[i];
  if (!line.trim()) continue;
  if (line.startsWith("|")) {
    const rows = [];
    while (i < md.length && md[i].startsWith("|")) rows.push(md[i++]);
    i--;
    children.push(table(rows));
    children.push(new Paragraph({ spacing: { before: 0, after: 120 }, children: [] }));
    continue;
  }
  let m;
  if ((m = line.match(/^# (.*)/))) {
    children.push(new Paragraph({ heading: HeadingLevel.TITLE, children: [new TextRun({ text: m[1], font: FONT })] }));
    children.push(new Paragraph({ spacing: { after: 240 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 18, color: TEAL, space: 4 } },
      children: [new TextRun({ text: "Information Security Management System (ISMS) · Supporting policy to ISMS-DEV-003",
        font: FONT, size: 20, color: NAVY })] }));
  } else if ((m = line.match(/^## (.*)/))) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1,
      border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: BLUE, space: 2 } }, children: runs(m[1]) }));
  } else if ((m = line.match(/^### (.*)/))) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: runs(m[1]) }));
  } else if ((m = line.match(/^#### (.*)/))) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_3, children: runs(m[1]) }));
  } else if ((m = line.match(/^(\s*)- (.*)/))) {
    children.push(new Paragraph({ numbering: { reference: "bullets", level: m[1].length >= 2 ? 1 : 0 }, children: runs(m[2]) }));
  } else if ((m = line.match(/^(\s*)(\d+)\. (.*)/))) {
    if (!m[1].length && (m[2] === "1" || !listInstance)) listInstance++;
    m = [m[0], m[1], m[3]];
    children.push(new Paragraph({ numbering: { reference: "numbers", level: m[1].length >= 2 ? 1 : 0, instance: listInstance },
      children: runs(m[2]) }));
  } else {
    children.push(new Paragraph({ children: runs(line.trim()) }));
  }
}

// ---------------------------------------------------------------- header/footer
const TABS = [{ type: TabStopType.CENTER, position: CONTENT_W / 2 }, { type: TabStopType.RIGHT, position: CONTENT_W }];
const header = new Header({ children: [new Paragraph({ tabStops: TABS,
  border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: NAVY, space: 4 } },
  children: [
    new TextRun({ text: "NERDIO", bold: true, color: NAVY, font: FONT, size: 22 }),
    new TextRun({ children: ["\t", META.title], font: FONT, size: 18, color: NAVY }),
    new TextRun({ children: ["\t", META.standard], font: FONT, size: 16, color: BLUE }),
  ] })] });

const footer = new Footer({ children: [new Paragraph({ tabStops: TABS,
  border: { top: { style: BorderStyle.SINGLE, size: 6, color: TEAL, space: 4 } },
  children: [
    new TextRun({ text: `CONFIDENTIAL | Version ${META.version} | ${META.year}`, font: FONT, size: 16, color: NAVY }),
    new TextRun({ children: ["\t", `${META.id} Threat Modelling`], font: FONT, size: 16, color: NAVY }),
    new TextRun({ children: ["\t",
      "Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], font: FONT, size: 16, color: NAVY }),
  ] })] });

// ---------------------------------------------------------------- document
const heading = (size, color, before, after) => ({
  run: { font: FONT, size, bold: true, color },
  paragraph: { spacing: { before, after }, keepNext: true, keepLines: true },
});
const doc = new Document({
  creator: "Nerdio Information Security",
  title: `${META.id} ${META.title}`,
  styles: {
    default: { document: { run: { font: FONT, size: 21, color: BODY }, paragraph: { spacing: { after: 100, line: 276 } } } },
    paragraphStyles: [
      { id: "Title", name: "Title", basedOn: "Normal", next: "Normal", run: { font: FONT, size: 44, bold: true, color: NAVY },
        paragraph: { spacing: { before: 120, after: 60 }, keepNext: true } },
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, ...heading(32, NAVY, 360, 140) },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, ...heading(26, BLUE, 240, 100) },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, ...heading(22, NAVY, 200, 80) },
    ],
  },
  numbering: { config: [
    { reference: "bullets", levels: [
      { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
      { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 270 } } } } ] },
    { reference: "numbers", levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } },
      { level: 1, format: LevelFormat.LOWER_LETTER, text: "%2)", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } } ] },
  ] },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1300, left: 1440, right: 1440, header: 600, footer: 600 } } },
    headers: { default: header }, footers: { default: footer }, children,
  }],
});

fs.mkdirSync(path.dirname(out), { recursive: true });
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log(`wrote ${out}`); });
