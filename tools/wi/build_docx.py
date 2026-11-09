#!/usr/bin/env python3
"""Word (.docx) and Markdown packages of the WIs, from WI/*.md and WI/images/.

    python3 tools/wi/build_docx.py            # the user and admin guides of both portals, and the automation document (DOCS)

Needs pandoc. Output next to the .md files: <name>.docx and <name>-markdown.zip (the .md with its images/).
The automation document (AUTOMATION) is first written again from ontap_restore/docs/AUTOMATION.md and docs/ACI-AUTOMATION.md,
which stay its source: edit those, not WI/<AUTOMATION>.md.
The .docx: A4 with 2 cm margins, Calibri, the first "# " heading as the title, the "*date*" line under it,
numbered figures as captions, bordered tables with a shaded header row (set on every table, so Word, LibreOffice,
Google Docs and Quick Look all show them), and "Page X of Y" in the footer.
"""
import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WI = os.path.join(ROOT, "WI")
AUTOMATION = "ONTAP-Restore-and-ACI-Web-UI-Automation"
DOCS = ("WI-ACI-Web-UI-User-Guide", "WI-ACI-Web-UI-Admin-Guide",
        "WI-ONTAP-Restore-Web-UI-User-Guide", "WI-ONTAP-Restore-Web-UI-Admin-Guide", AUTOMATION)
# The parts of the automation document: (letter, source in the repository).
AUTOMATION_PARTS = (("A", "ontap_restore/docs/AUTOMATION.md"), ("B", "docs/ACI-AUTOMATION.md"))
AUTOMATION_INTRO = """This document explains what the two portals run against other systems: when, where, the commands or APIs used, and which of them only read or also change the system.

| Part | Portal | Automation |
|-----|------------|------------------------------|
| A | ONTAP Restore Web UI | Ansible: NetApp ONTAP REST API from the bastion, OpenStack commands on the director through the management host |
| B | ACI Web UI | APIC REST API called directly from the application, without Ansible |

The sources are `ontap_restore/docs/AUTOMATION.md` (part A) and `docs/ACI-AUTOMATION.md` (part B) in the repository; both files are updated together with the code. How to use each portal is described in its User Guide and Admin Guide WIs."""
MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
          "December")
TEXT_WIDTH = 9638   # twips: A4 11906 - 2 x 1134 margins

F = '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri" />'
STYLES = {
    "Title": f'''<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title" /><w:basedOn w:val="Normal" /><w:next w:val="BodyText" /><w:link w:val="TitleChar" /><w:uiPriority w:val="10" /><w:qFormat />
    <w:pPr><w:spacing w:before="0" w:after="60" w:line="240" w:lineRule="auto" /><w:contextualSpacing /></w:pPr>
    <w:rPr>{F}<w:b /><w:bCs /><w:color w:val="1F3864" /><w:sz w:val="44" /><w:szCs w:val="44" /></w:rPr></w:style>''',
    "Date": f'''<w:style w:type="paragraph" w:styleId="Date"><w:name w:val="Date" /><w:basedOn w:val="Normal" /><w:next w:val="BodyText" /><w:qFormat />
    <w:pPr><w:keepNext /><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="8" w:color="1F4E79" /></w:pBdr><w:spacing w:before="0" w:after="240" /></w:pPr>
    <w:rPr>{F}<w:color w:val="595959" /><w:sz w:val="22" /><w:szCs w:val="22" /></w:rPr></w:style>''',
    "Heading1": f'''<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1" /><w:basedOn w:val="Normal" /><w:next w:val="BodyText" /><w:link w:val="Heading1Char" /><w:uiPriority w:val="9" /><w:qFormat />
    <w:pPr><w:keepNext /><w:keepLines /><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="4" w:color="BFBFBF" /></w:pBdr><w:spacing w:before="420" w:after="120" /><w:outlineLvl w:val="0" /></w:pPr>
    <w:rPr>{F}<w:b /><w:bCs /><w:color w:val="1F4E79" /><w:sz w:val="30" /><w:szCs w:val="30" /></w:rPr></w:style>''',
    "Heading2": f'''<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2" /><w:basedOn w:val="Normal" /><w:next w:val="BodyText" /><w:link w:val="Heading2Char" /><w:uiPriority w:val="9" /><w:unhideWhenUsed /><w:qFormat />
    <w:pPr><w:keepNext /><w:keepLines /><w:spacing w:before="300" w:after="100" /><w:outlineLvl w:val="1" /></w:pPr>
    <w:rPr>{F}<w:b /><w:bCs /><w:color w:val="2E74B5" /><w:sz w:val="25" /><w:szCs w:val="25" /></w:rPr></w:style>''',
    "Heading3": f'''<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3" /><w:basedOn w:val="Normal" /><w:next w:val="BodyText" /><w:link w:val="Heading3Char" /><w:uiPriority w:val="9" /><w:unhideWhenUsed /><w:qFormat />
    <w:pPr><w:keepNext /><w:keepLines /><w:spacing w:before="240" w:after="80" /><w:outlineLvl w:val="2" /></w:pPr>
    <w:rPr>{F}<w:b /><w:bCs /><w:color w:val="404040" /><w:sz w:val="22" /><w:szCs w:val="22" /></w:rPr></w:style>''',
    "BodyText": '''<w:style w:type="paragraph" w:styleId="BodyText"><w:name w:val="Body Text" /><w:basedOn w:val="Normal" /><w:link w:val="BodyTextChar" /><w:qFormat />
    <w:pPr><w:spacing w:before="60" w:after="120" /></w:pPr></w:style>''',
    "Compact": '''<w:style w:type="paragraph" w:customStyle="1" w:styleId="Compact"><w:name w:val="Compact" /><w:basedOn w:val="BodyText" /><w:qFormat />
    <w:pPr><w:spacing w:before="20" w:after="50" /></w:pPr></w:style>''',
    "Table": '''<w:style w:type="table" w:default="1" w:styleId="Table"><w:name w:val="Table" /><w:basedOn w:val="TableNormal" /><w:uiPriority w:val="59" /><w:qFormat />
    <w:pPr><w:spacing w:before="0" w:after="0" /></w:pPr><w:rPr><w:sz w:val="19" /><w:szCs w:val="19" /></w:rPr>
    <w:tblPr><w:tblInd w:w="0" w:type="dxa" /></w:tblPr></w:style>''',
    "Caption": '''<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption" /><w:basedOn w:val="Normal" /><w:link w:val="BodyTextChar" />
    <w:pPr><w:spacing w:before="40" w:after="240" /><w:jc w:val="center" /></w:pPr>
    <w:rPr><w:i /><w:iCs /><w:color w:val="595959" /><w:sz w:val="18" /><w:szCs w:val="18" /></w:rPr></w:style>''',
    "Figure": '''<w:style w:type="paragraph" w:customStyle="1" w:styleId="Figure"><w:name w:val="Figure" /><w:basedOn w:val="Normal" />
    <w:pPr><w:keepNext /><w:spacing w:before="120" w:after="0" /><w:jc w:val="center" /></w:pPr></w:style>''',
    "VerbatimChar": '''<w:style w:type="character" w:customStyle="1" w:styleId="VerbatimChar"><w:name w:val="Verbatim Char" /><w:basedOn w:val="BodyTextChar" />
    <w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas" /><w:color w:val="1F1F1F" /><w:sz w:val="19" /><w:szCs w:val="19" /><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2" /></w:rPr></w:style>''',
    "Hyperlink": '''<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink" /><w:basedOn w:val="BodyTextChar" />
    <w:rPr><w:color w:val="0563C1" /><w:u w:val="single" /></w:rPr></w:style>''',
}


def reference_docx(work):
    """pandoc's default reference.docx with the styles above, A4, and a page number footer."""
    ref = os.path.join(work, "ref")
    subprocess.run(["pandoc", "-o", os.path.join(work, "default.docx"), "--print-default-data-file", "reference.docx"], check=True)
    with zipfile.ZipFile(os.path.join(work, "default.docx")) as z:
        z.extractall(ref)
    path = os.path.join(ref, "word", "styles.xml")
    s = open(path, encoding="utf-8").read()
    s = s.replace('<w:rFonts w:asciiTheme="minorHAnsi" w:eastAsiaTheme="minorEastAsia" w:hAnsiTheme="minorHAnsi" w:cstheme="minorBidi" />', F, 1)
    s = re.sub(r'(<w:rPrDefault>.*?)<w:sz w:val="24" />\s*<w:szCs w:val="24" />\s*<w:lang w:val="en-US"',
               r'\1<w:sz w:val="21" /><w:szCs w:val="21" /><w:lang w:val="en-US"', s, count=1, flags=re.S)
    s = re.sub(r'(<w:pPrDefault>\s*<w:pPr>\s*)<w:spacing w:after="200" />', r'\1<w:spacing w:after="120" w:line="264" w:lineRule="auto" />', s, count=1)
    assert 'w:val="en-US"' in s and 'w:line="264"' in s
    for sid, body in STYLES.items():
        s, n = re.subn(r'<w:style [^>]*w:styleId="%s".*?</w:style>' % sid, lambda _m: body, s, count=1, flags=re.S)
        assert n == 1, sid
    open(path, "w", encoding="utf-8").write(s)

    path = os.path.join(ref, "word", "document.xml")
    d = open(path, encoding="utf-8").read()
    d = re.sub(r"<w:sectPr>.*?</w:sectPr>", '''<w:sectPr><w:footerReference w:type="default" r:id="rIdFtr1" />
      <w:footnotePr><w:numRestart w:val="eachSect" /></w:footnotePr><w:pgSz w:w="11906" w:h="16838" />
      <w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0" /></w:sectPr>''',
               d, count=1, flags=re.S)
    open(path, "w", encoding="utf-8").write(d)
    run = '<w:rPr><w:color w:val="7F7F7F" /><w:sz w:val="18" /><w:szCs w:val="18" /></w:rPr>'
    field = lambda code: (f'<w:r>{run}<w:fldChar w:fldCharType="begin" /></w:r><w:r>{run}<w:instrText xml:space="preserve"> {code} </w:instrText></w:r>'
                          f'<w:r>{run}<w:fldChar w:fldCharType="separate" /></w:r><w:r>{run}<w:t>1</w:t></w:r><w:r>{run}<w:fldChar w:fldCharType="end" /></w:r>')
    with open(os.path.join(ref, "word", "footer1.xml"), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:p><w:pPr><w:spacing w:before="0" w:after="0" />'
                f'<w:jc w:val="center" /></w:pPr><w:r>{run}<w:t xml:space="preserve">Page </w:t></w:r>{field("PAGE")}'
                f'<w:r>{run}<w:t xml:space="preserve"> of </w:t></w:r>{field("NUMPAGES")}</w:p></w:ftr>')
    for name, old, new in (
            (os.path.join("word", "_rels", "document.xml.rels"), "</Relationships>",
             '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Id="rIdFtr1" Target="footer1.xml" /></Relationships>'),
            ("[Content_Types].xml", "</Types>",
             '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" /></Types>')):
        p = os.path.join(ref, name)
        text = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(text.replace(old, new, 1))
    target = os.path.join(work, "reference-wi.docx")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for folder, _dirs, files in os.walk(ref):
            for name in files:
                full = os.path.join(folder, name)
                z.write(full, os.path.relpath(full, ref))
    return target


BORDER = '<w:{0} w:val="single" w:sz="4" w:space="0" w:color="A6A6A6" />'
BORDERS = "<w:tblBorders>" + "".join(BORDER.format(s) for s in ("top", "left", "bottom", "right", "insideH", "insideV")) + "</w:tblBorders>"
CELLMAR = ('<w:tblCellMar><w:top w:w="50" w:type="dxa" /><w:left w:w="100" w:type="dxa" />'
           '<w:bottom w:w="50" w:type="dxa" /><w:right w:w="100" w:type="dxa" /></w:tblCellMar>')


def fix_table(t):
    """Direct formatting on a pandoc table: full text width, borders, cell margins, shaded bold header row."""
    widths = [int(w) for w in re.findall(r'<w:gridCol w:w="(\d+)" />', t)]
    indent = re.search(r'<w:tblInd w:w="(\d+)"', t[:t.find("</w:tblPr>")])   # a table in a list item
    width = TEXT_WIDTH - (int(indent.group(1)) if indent else 0)
    new = [round(w * width / sum(widths)) for w in widths]
    new[-1] = width - sum(new[:-1])
    t = re.sub(r"<w:tblGrid>.*?</w:tblGrid>", "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}" />' for w in new) + "</w:tblGrid>",
               t, count=1, flags=re.S)
    t = t.replace('<w:tblW w:type="pct" w:w="5000" />', f'<w:tblW w:type="dxa" w:w="{width}" />', 1)
    # The borders after tblW, jc and tblInd: the order of the schema.
    t = re.sub(r"<w:tblW [^>]*/>(?:<w:jc [^>]*/>)?(?:<w:tblInd [^>]*/>)?", lambda m: m.group(0) + BORDERS, t, count=1)
    t = t.replace('<w:tblLayout w:type="fixed" />', '<w:tblLayout w:type="fixed" />' + CELLMAR, 1)
    parts = re.split(r"(?=<w:tr>)", t)
    out = [parts[0]]
    for row in parts[1:]:
        header = "<w:tblHeader" in row
        col = iter(range(10 ** 6))

        def cell(_m):
            w = new[min(next(col), len(new) - 1)]
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="DCE6F2" />' if header else ""
            return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa" />{shd}</w:tcPr>'
        row = re.sub(r"<w:tc><w:tcPr />", cell, row)
        if header:
            row = row.replace("<w:r><w:t", '<w:r><w:rPr><w:b /><w:bCs /><w:color w:val="1F3864" /></w:rPr><w:t')
        out.append(row)
    return "".join(out)


def postprocess(docx):
    with zipfile.ZipFile(docx) as zin:
        items = [(info, zin.read(info.filename)) for info in zin.infolist()]
    tmp = docx + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for info, data in items:
            if info.filename == "word/document.xml":
                data = re.sub(r"<w:tbl>.*?</w:tbl>", lambda m: fix_table(m.group(0)), data.decode("utf-8"), flags=re.S).encode("utf-8")
            elif info.filename == "[Content_Types].xml" and b'Extension="png"' not in data:
                data = data.replace(b'<Default Extension="xml"', b'<Default Extension="png" ContentType="image/png" /><Default Extension="xml"', 1)
            zout.writestr(info, data)
    shutil.move(tmp, docx)


def automation_part(letter, text):
    """One source document as part `letter`: its title as a "## Part …" heading, every other heading one level down,
    code blocks untouched. In a table, a code span with an escaped pipe is split around the pipe, because pandoc keeps
    the backslash inside code."""
    out, fence = [], False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            fence = not fence
        elif fence:
            pass
        elif line.startswith("# "):
            line = f"## Part {letter}. " + re.sub(r"^Automation\s+", "", line[2:].strip())
        elif re.match(r"^#{2,5} ", line):
            line = "#" + line
        elif line.lstrip().startswith("|") and "\\|" in line:
            line = re.sub(r"`([^`]*\\\|[^`]*)`", lambda m: "`" + m.group(1).replace("\\|", "`\\|`") + "`", line)
        out.append(line)
    return "\n".join(sized_tables(out)).strip() + "\n"


def sized_tables(lines):
    """Pipe tables with the dashes of their separator row in proportion to the text of each column, so pandoc gives a
    column of commands more room than a column such as # or Site (the sources use |---|---| everywhere)."""
    cells = lambda line: [c.strip() for c in re.split(r"(?<!\\)\|", line.strip()[1:-1])]
    sep = re.compile(r"^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$")
    out, i = list(lines), 0
    while i < len(out):
        if not (out[i].lstrip().startswith("|") and i + 1 < len(out) and sep.match(out[i + 1])):
            i += 1
            continue
        end = i + 2
        while end < len(out) and out[end].lstrip().startswith("|"):
            end += 1
        rows = [cells(out[j]) for j in range(i, end) if j != i + 1]
        n = len(cells(out[i + 1]))
        weight = [min(80, max(4, sum(len(r[c]) for r in rows if c < len(r)) / len(rows))) for c in range(n)]
        dashes = [max(3, round(w * 60 / sum(weight))) for w in weight]
        marks = cells(out[i + 1])
        indent = out[i + 1][:len(out[i + 1]) - len(out[i + 1].lstrip())]
        out[i + 1] = indent + "|" + "|".join((":" if m.startswith(":") else "") + "-" * d + (":" if m.endswith(":") else "")
                                             for m, d in zip(marks, dashes)) + "|"
        i = end
    return out


def automation_md():
    """WI/<AUTOMATION>.md from its sources, dated by the newest of them."""
    sources = [(letter, os.path.join(ROOT, path)) for letter, path in AUTOMATION_PARTS]
    newest = datetime.date.fromtimestamp(max(os.path.getmtime(path) for _, path in sources))
    parts = []
    for letter, path in sources:
        text = open(path, encoding="utf-8").read()
        text = text.replace("(see `ontap_restore/docs/AUTOMATION.md`)", "(see part A)")
        text = text.replace("This document explains", "This part explains", 1)
        parts.append(automation_part(letter, text))
    title = "# ONTAP Restore and ACI Web UI Automation Documentation"
    date = f"*{newest.day} {MONTHS[newest.month - 1]} {newest.year}*"
    with open(os.path.join(WI, AUTOMATION + ".md"), "w", encoding="utf-8") as f:
        f.write("\n\n".join([title, date, AUTOMATION_INTRO, *parts]))


def build(name, ref):
    if name == AUTOMATION:
        automation_md()
    md = os.path.join(WI, name + ".md")
    text = open(md, encoding="utf-8").read()
    m = re.search(r"^\*(\d{1,2} \w+ \d{4})\*\s*$", text, re.M)   # the date line becomes the Date paragraph under the title
    date = m.group(1) if m else ""
    body = text.replace(m.group(0), "", 1) if m else text
    docx = os.path.join(WI, name + ".docx")
    subprocess.run(["pandoc", "-f", "markdown", "-t", "docx", f"--reference-doc={ref}", f"--resource-path={WI}",
                    "--shift-heading-level-by=-1", "--columns=20", "-M", "lang=en-US", "-M", f"date={date}", "-o", docx],
                   input=body.encode("utf-8"), check=True)
    postprocess(docx)
    images = sorted(set(re.findall(r"\]\((images/[^)]+)\)", text)))
    missing = [i for i in images if not os.path.exists(os.path.join(WI, i))]
    if missing:
        sys.exit(f"{name}: missing images {missing}")
    with zipfile.ZipFile(os.path.join(WI, name + "-markdown.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.write(md, f"{name}/{name}.md")
        for image in images:
            z.write(os.path.join(WI, image), f"{name}/{image}")
    with zipfile.ZipFile(docx) as z:
        media = sum(1 for n in z.namelist() if n.startswith("word/media/"))
    print(f"{docx}: {os.path.getsize(docx) // 1024} KiB, {media} images (the .md has {len(images)}); {name}-markdown.zip")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as work:
        ref = reference_docx(work)
        for doc in sys.argv[1:] or DOCS:
            build(doc, ref)
